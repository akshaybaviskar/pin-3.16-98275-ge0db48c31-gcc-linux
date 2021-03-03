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
#include <iostream>
#include <fstream>
#include <string>
#include <cassert>
#include <syscall.h>
#include <memory>
#include "pin.H"
#include <unistd.h>
#include <sstream>
#include <cstdlib>
#include <sys/types.h>

using namespace std;

KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool",
      "o", "PintoolResults.out", "specify output file name");
KNOB<UINT64> KnobDetachLimit(KNOB_MODE_WRITEONCE, "pintool",
      "d", "42", "specify log2 of the instructions we count before detach");
UINT64 detach_limit = 0ul;
KNOB<UINT64> KnobSampleBlockLog2(KNOB_MODE_WRITEONCE, "pintool",
      "b", "17", "specify log2 of the instructions in a sample block");
UINT64 sample_block_log2 = 0ul;
KNOB<UINT64> KnobSampleRate(KNOB_MODE_WRITEONCE, "pintool",
      "r", "10", "specify log2 of the samples rate to trace");
UINT64 sample_rate = 0ul;

VOID ThreadStart(THREADID tid, CONTEXT *ctxt, INT32 flags, VOID *v) {
   //cout<<"started thread: "<<tid<<endl;
   // There is a new MLOG for every thread
   /*  MLOG * mlog = new MLOG(tid);
       mlog->stop_watch.Reset();

   // A thread will need to look up its MLOG, so save pointer in TLS
   PIN_SetThreadData(mlog_key, mlog, tid);*/
}

VOID ThreadFini(THREADID tid, const CONTEXT *ctxt, INT32 code, VOID *v) {
   // cout<<"finished thread: "<<tid<<endl;
   /*    MLOG * mlog = static_cast<MLOG*>(PIN_GetThreadData(mlog_key, tid));
         delete mlog;
         PIN_SetThreadData(mlog_key, 0, tid);  */  
}

/* ===================================================================== */
/* Instrumentation Functions                                             */
/* ===================================================================== */

int xx = 1;
#if 0
// Pin calls this function every time a new basic block is encountered
VOID Trace(TRACE trace, VOID *v) {
   if(xx)
   {
      ostringstream ss;
   
      ss<<"/bin/cat /proc/"<<getpid()<<"/maps";
      cout<<ss.str()<<endl;
      //system(ss.str().c_str());
      FILE* opp = popen(ss.str().c_str(),"r");

      char buff[255];
      while(fgets(buff, 255, (FILE*) opp))
      {
         cout<<buff;
      }
      ostringstream ss;
      stringstream filename;
      filename<<"vma.txt";
      fcnt++;
      ofstream opfile(filename.str().c_str());
      xx = 0;
      ss<<"/bin/cat /proc/"<<getpid()<<"/maps";
      cout<<ss.str()<<endl;
      FILE* opp = popen(ss.str().c_str(),"r");
      char* line = NULL;
      size_t len = 0;
      ssize_t read;

      while((read = getline(&line, &len, opp)) != -1)
      {
         opfile<<line;
      }
      xx = 0;
   }          

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
            // Record this virtual address in the buffer only when we need to sample
            INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)IsSample,
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
#endif

VOID RecordMemRead(VOID * ip, VOID * addr) {
    //if (!Record) return;
    printf("%p\n", addr);
}


VOID RecordMemWrite(VOID * ip, VOID * addr) {
   // if (!Record) return;
    //printf("/*%p: W %p\n", ip, addr);
    printf("%p\n", addr);
}

VOID Instruction(INS ins, VOID *v) {
   if(xx)
   {
      ostringstream ss;
   
    /*  ss<<"/bin/cat /proc/"<<getpid()<<"/maps";
      cout<<ss.str()<<endl;
      //system(ss.str().c_str());
      FILE* opp = popen(ss.str().c_str(),"r");

      char buff[255];
      while(fgets(buff, 255, (FILE*) opp))
      {
         cout<<buff;
      }
      ss.str("");*/
      stringstream filename;
      filename<<"vma.txt";
      ofstream opfile(filename.str().c_str());
      xx = 0;
      ss<<"/bin/cat /proc/"<<getpid()<<"/maps";
      cout<<ss.str()<<endl;
      FILE* opp = popen(ss.str().c_str(),"r");
      char* line = NULL;
      size_t len = 0;
      ssize_t read;

      while((read = getline(&line, &len, opp)) != -1)
      {
         opfile<<line;
      }
      xx = 0;
   }          
    UINT32 memOperands = INS_MemoryOperandCount(ins);
    for (UINT32 memOp = 0; memOp < memOperands; memOp++) {
        if (INS_MemoryOperandIsRead(ins, memOp)) {
            INS_InsertPredicatedCall(
                                 ins, IPOINT_BEFORE, (AFUNPTR)RecordMemRead,
                                 IARG_INST_PTR,
                                 IARG_MEMORYOP_EA, memOp,
                                 IARG_END);
        }
        if (INS_MemoryOperandIsWritten(ins, memOp)) {
             INS_InsertPredicatedCall(
                                 ins, IPOINT_BEFORE, (AFUNPTR)RecordMemWrite,
                                 IARG_INST_PTR,
                                 IARG_MEMORYOP_EA, memOp,
                                 IARG_END);
        }
    }
}


/* ===================================================================== */
/* Syscalls Callbacks                                                    */
/* ===================================================================== */
VOID SyscallEntry(THREADID tid, CONTEXT *ctxt, SYSCALL_STANDARD std, VOID *v) {
   /*    MLOG * mlog = static_cast<MLOG*>(PIN_GetThreadData(mlog_key, tid));*/
}

VOID SyscallExit(THREADID tid, CONTEXT *ctxt, SYSCALL_STANDARD std, VOID *v) {
   auto syscall_num = PIN_GetSyscallNumber(ctxt, std);
   // cout<<"syscall "<<syscall_num<<endl;
   if (((syscall_num >= 9) && (syscall_num <= 12)) || (syscall_num == 25)) {
      ostringstream ss;
      stringstream filename;
      filename<<"vma.txt";
      ofstream opfile(filename.str().c_str());
      xx = 0;
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
}

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

   // Initialize pin
   if (PIN_Init(argc, argv)) return Usage();

   detach_limit = KnobDetachLimit.Value();

   cout<<"Obtained detach limit value: "<<detach_limit<<endl;
   sample_block_log2 = KnobSampleBlockLog2.Value();
   sample_rate = KnobSampleRate.Value();
   if (sample_rate == 0) std::cerr << "Must use sample rate > 0.\n";

   // Initialize the buffer and set up the callback to process the buffer.
   //cout<<"definetracebuffer "<<num_buffer_pages<<endl;
 //  buffer_id = PIN_DefineTraceBuffer(
 //        sizeof(ADDRINT), num_buffer_pages, BufferFull, 0);
 //  if(buffer_id == BUFFER_ID_INVALID) {
 //     std::cerr << "Error: could not allocate initial buffer." << std::endl;
 //     return 1;
 //  }

   // Add callbacks related to threads
   PIN_AddThreadStartFunction(ThreadStart, 0);
   PIN_AddThreadFiniFunction(ThreadFini, 0);

   // Register Trace to be called to instrument with trace granularity
   INS_AddInstrumentFunction(Instruction, 0);

   // Register Analysis routines to be called before/after syscalls
   PIN_AddSyscallEntryFunction(SyscallEntry, 0);
   PIN_AddSyscallExitFunction(SyscallExit, 0);

   // Never returns
   PIN_StartProgram();

   return 0;
}

