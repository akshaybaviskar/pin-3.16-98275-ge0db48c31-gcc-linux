/*BEGIN_LEGAL 
  Intel Open Source License 

  Copyright (c) 2002-2013 Intel Corporation. All rights reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are
met:

Redistributions of source code must retain the above copyright notice,
this list of conditions and the following disclaimer.  Redistributions
in binary form must reproduce the above copyright notice, this list of
conditions and the following disclaimer in the documentation and/or
other materials provided with the distribution.  Neither the name of
the Intel Corporation nor the names of its contributors may be used to
endorse or promote products derived from this software without
specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE INTEL OR
ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
END_LEGAL */
/*
 *  This file contains an ISA-portable PIN tool for tracing memory accesses.
 */
#define _XOPEN_SOURCE 700
#include <fcntl.h> /* open */
#include <stdint.h> /* uint64_t  */
#include <stdio.h> /* printf */
#include <stdlib.h> /* size_t */
#include <unistd.h> /* pread, sysconf */

#include <iostream>
#include <fstream>
#include <string>
#include <cassert>
#include <syscall.h>
#include <sys/mman.h>
#include <errno.h>

#include "pin.H"

#define PAGEMAP_LENGTH 8

typedef struct {
   uint64_t pfn : 55;
   unsigned int soft_dirty : 1;
   unsigned int file_page : 1;
   unsigned int swapped : 1;
   unsigned int present : 1;
} PagemapEntry;

typedef struct { 
   unsigned int huge : 1;
   unsigned int thp : 1; 
} PageflagEntry;

#define	WARMUP_TO_RECORD_LOG	(ADDRINT)0xdeadbeefdeadbeef
#define	RECORD_TO_WARMUP_LOG	(ADDRINT)0xbeefdeadbeefdead

using namespace std;
// The configuration file for the memory system is passed via "gcc -include".
// The header file initializes the page_table, which is shared between threads,
// and specifies core factory method via a corresponding function.

KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool",
      "o", "PintoolResults.out", "specify output file namw");
KNOB<UINT64> KnobDetachLimit(KNOB_MODE_WRITEONCE, "pintool",
      "d", "42", "specify log2 of the instructions we count before detach");
UINT64 detach_limit = 0ul;
KNOB<UINT64> KnobSampleBlockLog2(KNOB_MODE_WRITEONCE, "pintool",
      "b", "17", "specify log2 of the instructions in a sample block");
UINT64 sample_block_log2 = 0ul;
KNOB<UINT64> KnobSampleRate(KNOB_MODE_WRITEONCE, "pintool",
      "r", "10", "specify log2 of the samples rate to trace");
UINT64 sample_rate = 0ul;

FILE *pagemap_fptr;
FILE *kpageflags_fptr;
FILE *kpagecount_fptr;
#if 1
// The ID of the buffer
BUFFER_ID buffer_id;
UINT32 num_buffer_pages = 1ul<<6;

int vma_cnt = 1;
// Thread specific data
TLS_KEY mlog_key;
PIN_LOCK lock;

uint64_t get_pagecount(uintptr_t pfn) 
{ 
   unsigned long offset = (unsigned long)pfn * PAGEMAP_LENGTH;
   uint64_t count = 0;

   if(fseek(kpagecount_fptr, (unsigned long)offset, SEEK_SET) != 0) {
      fprintf(stderr, "Failed to seek pagemap to proper location\n");
      return 1;
   }

   fread(&count, 1, PAGEMAP_LENGTH, kpagecount_fptr);
   if(ferror(kpagecount_fptr))
   {
      fprintf(stderr, "Error while reading pagemap.\n");
      return 1;
   }

   return count;
}


/* Parse the pagemap entry for the given virtual address.
 *
 * @param[out] entry      the parsed entry
 * @param[in]  pfn        pfn to read flags for
 * @return 0 for success, 1 for failure
 */
int pageflag_get_entry(PageflagEntry *entry, uintptr_t paddr) 
{ 
    unsigned long offset = (unsigned long)paddr / sysconf(_SC_PAGESIZE) * PAGEMAP_LENGTH;

   if(fseek(kpageflags_fptr, (unsigned long)offset, SEEK_SET) != 0) {
      fprintf(stderr, "Failed to seek pagemap to proper location\n");
      return 1;
   }

   uint64_t flags = 0; 
   fread(&flags, 1, PAGEMAP_LENGTH-1, kpageflags_fptr);
   if(ferror(kpageflags_fptr))
   {
      fprintf(stderr, "Error while reading pagemap.\n");
      return 1;
   }

   entry->huge = (flags >> 17) & 1;
   entry->thp = (flags >> 22) & 1;
   return 0;
}

//return 0 if success, else 1
int vpn_to_pfn(PagemapEntry *entry, intptr_t vaddr) {

   unsigned long offset = (unsigned long)vaddr / sysconf(_SC_PAGESIZE) * PAGEMAP_LENGTH;

   if(fseek(pagemap_fptr, (unsigned long)offset, SEEK_SET) != 0) {
      fprintf(stderr, "Failed to seek pagemap to proper location\n");
      return 1;
   }

   uint64_t page_frame_number = 0;
   fread(&page_frame_number, 1, PAGEMAP_LENGTH-1, pagemap_fptr);
   if(ferror(pagemap_fptr))
   {
      fprintf(stderr, "Error while reading pagemap.\n");
      return 1;
   }
   page_frame_number &= 0x7FFFFFFFFFFFFF;

   entry->pfn = page_frame_number;
   return 0;
}

int virt_to_phys_user(uintptr_t *paddr, uintptr_t vaddr)
{
   PagemapEntry entry;

   if(pagemap_fptr == NULL)
   {
      cout<<"unable to open pagemap file"<<endl;
      return 1;
   }

   if (vpn_to_pfn(&entry, vaddr)) {
      return 1;
   }
   *paddr = (entry.pfn * sysconf(_SC_PAGE_SIZE)) + (vaddr % sysconf(_SC_PAGE_SIZE));
   return 0;
}

// MLOG - thread specific data that is not handled by the buffering API.
class MLOG {
   public:
      MLOG(THREADID tid)
         : total_ins_count(0), ins_count(0), sample_count(0),
         prev_sample_phase(0), sample_phase(0),
         //	stop_watch(), core(CreateCore()),
         syscall_num(0), syscall_arg0(0), syscall_arg1(0) {
            // The file name is "PintoolResults.out-ProcessID-ThreadID"
            std::string output_file_name = KnobOutputFile.Value() /*+ "-" +
                                                                    decstr(PIN_GetPid()) */+ "-" + decstr(tid);
               output_file.open(output_file_name.c_str());

            if (!output_file) {
               std::cerr << "Error: could not open output file." << std::endl;
               exit(1);
            }
            output_file << std::hex << std::scientific << std::setprecision(3);
         }

      ~MLOG() {
         output_file.close();
      }

      /* Public class members */
      UINT64 total_ins_count;	// the running count of instructions
      UINT64 ins_count;	// the running count of sampled instructions
      UINT64 sample_count;
      UINT64 prev_sample_phase;
      UINT64 sample_phase;

      //	Stopwatch stop_watch;	// the running stop watch for thread execution time
      //	CoreType core;	// per core memory system
      std::ofstream output_file;	// where to write the results

      // 3 integers to save the context before syscalls
      UINT64 syscall_num;
      UINT64 syscall_arg0;
      UINT64 syscall_arg1;
};

/* ===================================================================== */
/* Callback Functions                                                    */
/* ===================================================================== */

// Add BBLNumIns to the total instruction counter
VOID PIN_FAST_ANALYSIS_CALL AccumulateTotalIns(UINT32 BBLNumIns, THREADID tid) {
   MLOG * mlog = static_cast<MLOG*>(PIN_GetThreadData(mlog_key, tid));
   if(vma_cnt == 1)
   {
      ostringstream ss;
      stringstream filename;
      string outputfileval = KnobOutputFile.Value();
      size_t pos = outputfileval.find("/", 69);

      //filename<<KnobOutputFile.Value()<<"/vma_"<<vma_cnt;
      filename<<outputfileval.substr(0,pos)<<"/VMAs/vma_"<<vma_cnt;
      mlog->output_file<<"vma_"<<dec<<vma_cnt<<endl;
      vma_cnt++;
      ofstream opfile(filename.str().c_str());
      //ss<<"/bin/cat /proc/"<<PIN_GetPid()<<"/maps";
      ss<<"/bin/cat /proc/"<<getpid()<<"/maps";

      FILE* opp = popen(ss.str().c_str(),"r");
      char* line = NULL;
      size_t len = 0;
      ssize_t read;

      while((read = getline(&line, &len, opp)) != -1)
      {
         opfile<<line;
      }
   }          

   mlog->total_ins_count += BBLNumIns;

   mlog->prev_sample_phase = mlog->sample_phase;
   UINT64 sample_num = (mlog->total_ins_count) >> sample_block_log2;
   mlog->sample_phase = sample_num & ((1ul<<sample_rate)-1);

   if (mlog->total_ins_count >= (1ul<<detach_limit)) {
      PIN_ExitApplication(0);
   }
}

// Add BBLNumIns to the instruction counter
VOID PIN_FAST_ANALYSIS_CALL AccumulateIns(UINT32 BBLNumIns, THREADID tid) {
   MLOG * mlog = static_cast<MLOG*>(PIN_GetThreadData(mlog_key, tid));
   mlog->ins_count += BBLNumIns;
}

// Returns true if the instruction counter lies where we need to warmup
ADDRINT PIN_FAST_ANALYSIS_CALL IsSample(THREADID tid) {
   MLOG * mlog = static_cast<MLOG*>(PIN_GetThreadData(mlog_key, tid));
   return ((mlog->sample_phase == 0) || (mlog->sample_phase == 1));
}

// Returns true if the instruction counter lies where we need to sample
ADDRINT PIN_FAST_ANALYSIS_CALL IsRecord(THREADID tid) {
   MLOG * mlog = static_cast<MLOG*>(PIN_GetThreadData(mlog_key, tid));
   return (mlog->sample_phase == 1);
}

// Returns true if the instruction counter lies where we need to sample
ADDRINT PIN_FAST_ANALYSIS_CALL IsWarmupToRecordChange(THREADID tid) {
   MLOG * mlog = static_cast<MLOG*>(PIN_GetThreadData(mlog_key, tid));
   return ((mlog->prev_sample_phase != 1) && (mlog->sample_phase == 1));
}

// Returns true if the instruction counter lies where we need to sample
ADDRINT PIN_FAST_ANALYSIS_CALL IsRecordToWarmupChange(THREADID tid) {
   MLOG * mlog = static_cast<MLOG*>(PIN_GetThreadData(mlog_key, tid));
   return ((mlog->prev_sample_phase != 0) && (mlog->sample_phase == 0));
}

// Print report of the program state to output file
void PrintReport(MLOG * mlog) {
   std::string sample_prefix = "Sample " + decstr(mlog->sample_count);
   mlog->output_file << "########## Begin " << sample_prefix << " ##########\n";
   mlog->output_file << "/ElapsedMinutes: " <<
      //		mlog->stop_watch.ElapsedMinutes() << "\n";
      mlog->output_file << "/InstructionCount: " <<
      static_cast<double>(1ul<<sample_block_log2) << "\n";
   //	mlog->core.PrintInformation(mlog->output_file, "");
   mlog->output_file << "########## End " << sample_prefix << " ##########\n";
}

// This will be called when the buffer fills up, or the thread exits.
VOID* BufferFull(BUFFER_ID buffer_id, THREADID tid, const CONTEXT *ctxt,
      VOID *buffer, UINT64 numElements, VOID *v) {
   MLOG * mlog = static_cast<MLOG*>(PIN_GetThreadData(mlog_key, tid));

   //VirtAddrType *buffer_start = static_cast<VirtAddrType*>(buffer);
   uint64_t *buffer_start = static_cast<uint64_t*>(buffer);
   //try
   {
      PIN_GetLock(&lock, tid+1);	// accessing the core and the underlying
      // shared page table is a crirical code section.
      for (UINT64 i=0 ; i<numElements ; ++i) {
         if (buffer_start[i] == WARMUP_TO_RECORD_LOG) {
            ++(mlog->sample_count);
            mlog->output_file<<hex<<setfill('0')<<setw(16)<<buffer_start[i]<<endl;
            //mlog->core.ResetCounters();
            continue;
         } else if (buffer_start[i] == RECORD_TO_WARMUP_LOG) {
            //	PrintReport(mlog);
            mlog->output_file<<hex<<setfill('0')<<setw(16)<<buffer_start[i]<<endl;
            continue;
         }			

         #if 1
         //Code to collect PFN and huge page info
         uint64_t vaddr = buffer_start[i];
         uint64_t paddr = 0;
         PageflagEntry entry;

         if(virt_to_phys_user(&paddr, vaddr))
         {
            cout<<"failed to get pfn"<<endl;
            exit(-1);
         }
         
         uint64_t pfn = paddr >> 12;
         if(pageflag_get_entry(&entry, paddr))
         {
            cout<<"failed to get flag info"<<endl;
            exit(-1);
         }

         bool is_huge = entry.huge || entry.thp;
   //       
   //      // Record memory access in the core
         mlog->output_file<<hex<<setfill('0')<<setw(16)<<buffer_start[i]<<" "<<paddr<<" "<<is_huge<<" ";
         mlog->output_file<<dec<<get_pagecount(pfn)<<endl;;
   //      #else
   //      mlog->output_file<<hex<<setfill('0')<<setw(16)<<buffer_start[i]<<endl;
         #endif
      }
      PIN_ReleaseLock(&lock);
   }
   /* catch (const std::exception& e) {
      mlog->output_file << "Unsuccessful termination, we caught an exception:\n";
      mlog->output_file << e.what() << std::endl;
      throw e;
      }*/
   return buffer;
}

VOID ThreadStart(THREADID tid, CONTEXT *ctxt, INT32 flags, VOID *v) {
   // There is a new MLOG for every thread
   MLOG * mlog = new MLOG(tid);
   //	mlog->stop_watch.Reset();

   // A thread will need to look up its MLOG, so save pointer in TLS
   PIN_SetThreadData(mlog_key, mlog, tid);
}

VOID ThreadFini(THREADID tid, const CONTEXT *ctxt, INT32 code, VOID *v) {
   MLOG * mlog = static_cast<MLOG*>(PIN_GetThreadData(mlog_key, tid));
   delete mlog;
   PIN_SetThreadData(mlog_key, 0, tid);    
}

/* ===================================================================== */
/* Instrumentation Functions                                             */
/* ===================================================================== */

// Pin calls this function every time a new basic block is encountered
VOID Trace(TRACE trace, VOID *v) {

   for(BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl=BBL_Next(bbl)) {
      // Insert a call to AccumulateTotalIns before every bbl,
      // passing the number of instructions
      BBL_InsertCall(bbl, IPOINT_ANYWHERE, (AFUNPTR)AccumulateTotalIns,
            IARG_FAST_ANALYSIS_CALL,
            IARG_UINT32, BBL_NumIns(bbl),
            IARG_THREAD_ID,
            IARG_END);

      // Update the instructions counter only when we need to record
      BBL_InsertIfCall(bbl, IPOINT_BEFORE, (AFUNPTR)IsRecord,
            IARG_FAST_ANALYSIS_CALL,
            IARG_THREAD_ID,
            IARG_END);
      BBL_InsertThenCall(bbl, IPOINT_BEFORE, (AFUNPTR)AccumulateIns,
            IARG_FAST_ANALYSIS_CALL,
            IARG_UINT32, BBL_NumIns(bbl),
            IARG_THREAD_ID,
            IARG_END);

      // Log every warmup --> record phase change
      INS_InsertIfCall(BBL_InsHead(bbl), IPOINT_BEFORE,
            (AFUNPTR)IsWarmupToRecordChange,
            IARG_FAST_ANALYSIS_CALL,
            IARG_THREAD_ID,
            IARG_END);
      INS_InsertFillBufferThen(BBL_InsHead(bbl), IPOINT_BEFORE, buffer_id,
            IARG_ADDRINT, WARMUP_TO_RECORD_LOG, 0,
            IARG_END);

      // Log every record --> warmup phase change
      INS_InsertIfCall(BBL_InsHead(bbl), IPOINT_BEFORE,
            (AFUNPTR)IsRecordToWarmupChange,
            IARG_FAST_ANALYSIS_CALL,
            IARG_THREAD_ID,
            IARG_END);
      INS_InsertFillBufferThen(BBL_InsHead(bbl), IPOINT_BEFORE, buffer_id,
            IARG_ADDRINT, RECORD_TO_WARMUP_LOG, 0,
            IARG_END);

      // Go over the instructions, and look for the memory references
      for(INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins=INS_Next(ins)) {
         UINT32 memoryOperands = INS_MemoryOperandCount(ins);
         for (UINT32 memOp = 0; memOp < memoryOperands; memOp++) {
            if (INS_MemoryOperandIsRead(ins, memOp))
            {  	
               INS_InsertIfPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)IsSample,
                     IARG_FAST_ANALYSIS_CALL,
                     IARG_THREAD_ID,
                     IARG_END);
               INS_InsertFillBufferThen(ins, IPOINT_BEFORE, buffer_id,
                     IARG_MEMORYOP_EA, memOp, 0,
                     IARG_END);
            }
            // Record this virtual address in the buffer only when we need to sample
            if (INS_MemoryOperandIsWritten(ins, memOp))
            {  	
               INS_InsertIfPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)IsSample,
                     IARG_FAST_ANALYSIS_CALL,
                     IARG_THREAD_ID,
                     IARG_END);
               INS_InsertFillBufferThen(ins, IPOINT_BEFORE, buffer_id,
                     IARG_MEMORYOP_EA, memOp, 0,
                     IARG_END);
            }
         }
      }
   }
}

/* ===================================================================== */
/* Syscalls Callbacks                                                    */
/* ===================================================================== */

VOID SyscallEntry(THREADID tid, CONTEXT *ctxt, SYSCALL_STANDARD std, VOID *v) {
   MLOG * mlog = static_cast<MLOG*>(PIN_GetThreadData(mlog_key, tid));
   mlog->syscall_num = PIN_GetSyscallNumber(ctxt, std);
   if ((mlog->syscall_num == SYS_mmap) || (mlog->syscall_num == SYS_munmap)) {
      mlog->syscall_arg0 = PIN_GetSyscallArgument(ctxt, std, 0);
      mlog->syscall_arg1 = PIN_GetSyscallArgument(ctxt, std, 1);
   }
}

VOID SyscallExit(THREADID tid, CONTEXT *ctxt, SYSCALL_STANDARD std, VOID *v) {
   MLOG* mlog = static_cast<MLOG*>(PIN_GetThreadData(mlog_key, tid));

   if (((mlog->syscall_num >= 9) && (mlog->syscall_num <= 12)) || (mlog->syscall_num == 25))
   {
      ostringstream ss;
      stringstream filename; 
      string outputfileval = KnobOutputFile.Value();
      size_t pos = outputfileval.find("/", 69);

      // filename<<KnobOutputFile.Value()<<"/vma_"<<vma_cnt;
      filename<<outputfileval.substr(0,pos)<<"/VMAs/vma_"<<vma_cnt;
      mlog->output_file<<"vma_"<<dec<<vma_cnt<<endl;
      vma_cnt++;
      ofstream opfile(filename.str().c_str());
      ss<<"/bin/cat /proc/"<<PIN_GetPid()<<"/maps";

      FILE* opp = popen(ss.str().c_str(),"r");
      char* line = NULL;
      size_t len = 0;
      ssize_t read;

      while((read = getline(&line, &len, opp)) != -1)
      {
         opfile<<line;
      }
   }
}

#endif
/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */

INT32 Usage() {
   std::cerr << KNOB_BASE::StringKnobSummary() << "\n";
   return -1;
}
/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */

int main(int argc, char *argv[]) {
   // assert that the two types for virtual addresses are the same:
   // VirtAddrType	-	defined at Source/Common/Common.h
   // ADDRINT		-	defined at pin.H
   //TODO: check this and enable it : assert((bool)(std::is_same<uint64_t, ADDRINT>::value));
   char pagemap_file[BUFSIZ];
   char pageflags_file[BUFSIZ];
   char pagecount_file[BUFSIZ];
   //int pagemap_fd;
   pid_t pid;
   //PageflagEntry entry;
   errno = 0;
   pid = PIN_GetPid();

   snprintf(pagemap_file, sizeof(pagemap_file), "/proc/%ju/pagemap", (uintmax_t)pid);
   pagemap_fptr = fopen(pagemap_file, "rb");

   if(!pagemap_fptr)
   {
      printf("unable to open %s \n", pagemap_file);
      exit(-1);
   }

   snprintf(pageflags_file, sizeof(pageflags_file), "/proc/kpageflags");
   kpageflags_fptr = fopen(pageflags_file, "rb");
   auto x = errno;
   printf("kpageflags_ptr = %p , errno = %d \n", kpageflags_fptr, x);
   if(!kpageflags_fptr)
   {
      printf("unable to open %s error: %d\n", pageflags_file, errno);
      exit(-1);
   }

   snprintf(pagecount_file, sizeof(pagecount_file), "/proc/kpagecount");
   kpagecount_fptr = fopen(pagecount_file, "rb");
   if(!kpagecount_fptr)
   {
      printf("unable to open %s \n", pagecount_file);
      exit(-1);
   }

 // Initialize the pin lock
   PIN_InitLock(&lock);

   // Initialize pin
   if (PIN_Init(argc, argv)) return Usage();

   detach_limit = KnobDetachLimit.Value();
   sample_block_log2 = KnobSampleBlockLog2.Value();
   sample_rate = KnobSampleRate.Value();
   if (sample_rate == 0) std::cerr << "Must use sample rate > 0.\n";

   // Initialize the buffer and set up the callback to process the buffer.
   buffer_id = PIN_DefineTraceBuffer(
         sizeof(ADDRINT), num_buffer_pages, BufferFull, 0);
   if(buffer_id == BUFFER_ID_INVALID) {
      std::cerr << "Error: could not allocate initial buffer." << std::endl;
      return 1;
   }

   // Initialize thread-specific data not handled by buffering api.
   mlog_key = PIN_CreateThreadDataKey(0);

   // Add callbacks related to threads
   PIN_AddThreadStartFunction(ThreadStart, 0);
   PIN_AddThreadFiniFunction(ThreadFini, 0);

   // Register Trace to be called to instrument with trace granularity
   TRACE_AddInstrumentFunction(Trace, 0);

   // Register Analysis routines to be called before/after syscalls
   PIN_AddSyscallEntryFunction(SyscallEntry, 0);
   PIN_AddSyscallExitFunction(SyscallExit, 0);

   // Never returns
   PIN_StartProgram();
   fclose(pagemap_fptr);
   fclose(kpageflags_fptr);
   fclose(kpagecount_fptr);

   return 0;
}
