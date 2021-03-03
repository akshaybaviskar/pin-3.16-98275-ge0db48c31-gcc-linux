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
//#include "Common/Common.h"
//#include "Common/Stopwatch.hh"

#define	WARMUP_TO_RECORD_LOG	(ADDRINT)0xdeadbeefdeadbeef
#define	RECORD_TO_WARMUP_LOG	(ADDRINT)0xbeefdeadbeefdead

// The configuration file for the memory system is passed via "gcc -include".
// The header file initializes the page_table, which is shared between threads,
// and specifies core factory method via a corresponding function.

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

// The ID of the buffer
BUFFER_ID buffer_id;
UINT32 num_buffer_pages = 1ul<<5;

// Thread specific data
TLS_KEY mlog_key;
PIN_LOCK lock;

 /*MLOG - thread specific data that is not handled by the buffering API.
class MLOG {
public:
	MLOG(THREADID tid)
		: total_ins_count(0), ins_count(0), sample_count(0),
		prev_sample_phase(0), sample_phase(0),
		stop_watch(), core(CreateCore()),
		syscall_num(0), syscall_arg0(0), syscall_arg1(0) {
		// The file name is "PintoolResults.out-ProcessID-ThreadID"
		std::string output_file_name = KnobOutputFile.Value() + "-" +
			decstr(PIN_GetPid()) + "-" + decstr(tid);
   		output_file.open(output_file_name);
   		
   		if (!output_file) {
   			std::cerr << "Error: could not open output file." << std::endl;
   			exit(1);
   		}
   		output_file << std::hex << std::scientific << std::setprecision(3);
	}
    
    ~MLOG() {
    	output_file.close();
    }*/

	/* Public class members */
/*	UINT64 total_ins_count;	// the running count of instructions
	UINT64 ins_count;	// the running count of sampled instructions
	UINT64 sample_count;
	UINT64 prev_sample_phase;
	UINT64 sample_phase;
	
	Stopwatch stop_watch;	// the running stop watch for thread execution time
	CoreType core;	// per core memory system
	std::ofstream output_file;	// where to write the results
	
	// 3 integers to save the context before syscalls
	UINT64 syscall_num;
	UINT64 syscall_arg0;
	UINT64 syscall_arg1;
};*/

/* ===================================================================== */
/* Callback Functions                                                    */
/* ===================================================================== */

// Add BBLNumIns to the total instruction counter
VOID PIN_FAST_ANALYSIS_CALL AccumulateTotalIns(UINT32 BBLNumIns, THREADID tid) {
  /*  MLOG * mlog = static_cast<MLOG*>(PIN_GetThreadData(mlog_key, tid));
	mlog->total_ins_count += BBLNumIns;

    mlog->prev_sample_phase = mlog->sample_phase;
    UINT64 sample_num = (mlog->total_ins_count) >> sample_block_log2;
    mlog->sample_phase = sample_num & ((1ul<<sample_rate)-1);

    if (mlog->total_ins_count >= (1ul<<detach_limit)) {
        PIN_ExitApplication(0);
    }*/
}

// Add BBLNumIns to the instruction counter
VOID PIN_FAST_ANALYSIS_CALL AccumulateIns(UINT32 BBLNumIns, THREADID tid) {
/*    MLOG * mlog = static_cast<MLOG*>(PIN_GetThreadData(mlog_key, tid));
	mlog->ins_count += BBLNumIns;*/
}

// Returns true if the instruction counter lies where we need to warmup
ADDRINT PIN_FAST_ANALYSIS_CALL IsSample(THREADID tid) {
   /* MLOG * mlog = static_cast<MLOG*>(PIN_GetThreadData(mlog_key, tid));
	return ((mlog->sample_phase == 0) || (mlog->sample_phase == 1));*/
   return true;
}

// Returns true if the instruction counter lies where we need to sample
ADDRINT PIN_FAST_ANALYSIS_CALL IsRecord(THREADID tid) {
  /*  MLOG * mlog = static_cast<MLOG*>(PIN_GetThreadData(mlog_key, tid));
	return (mlog->sample_phase == 1);*/
   return true;
}

// Returns true if the instruction counter lies where we need to sample
ADDRINT PIN_FAST_ANALYSIS_CALL IsWarmupToRecordChange(THREADID tid) {
 /*   MLOG * mlog = static_cast<MLOG*>(PIN_GetThreadData(mlog_key, tid));
    return ((mlog->prev_sample_phase != 1) && (mlog->sample_phase == 1));*/
   return true;
}

// Returns true if the instruction counter lies where we need to sample
ADDRINT PIN_FAST_ANALYSIS_CALL IsRecordToWarmupChange(THREADID tid) {
/*    MLOG * mlog = static_cast<MLOG*>(PIN_GetThreadData(mlog_key, tid));
    return ((mlog->prev_sample_phase != 0) && (mlog->sample_phase == 0));*/
   return true;
}

// Print report of the program state to output file
/*void PrintReport(MLOG * mlog) {
	std::string sample_prefix = "Sample " + decstr(mlog->sample_count);
	mlog->output_file << "########## Begin " << sample_prefix << " ##########\n";
	mlog->output_file << "/ElapsedMinutes: " <<
		mlog->stop_watch.ElapsedMinutes() << "\n";
	mlog->output_file << "/InstructionCount: " <<
		static_cast<double>(1ul<<sample_block_log2) << "\n";
	mlog->core.PrintInformation(mlog->output_file, "");
	mlog->output_file << "########## End " << sample_prefix << " ##########\n"/
}*/

// This will be called when the buffer fills up, or the thread exits.
VOID* BufferFull(BUFFER_ID buffer_id, THREADID tid, const CONTEXT *ctxt, VOID *buffer, UINT64 numElements, VOID *v) {
   int n = sizeof(buffer);
   //cout<<"buffer size "<<n<<endl;
   //uint64_t* buffer_start = static_cast<uint64_t*>(buffer);
   for(int i=0;i<n;i++)
   {
     // cout<<hex<<(uint64_t)buffer_start[i]<<endl;
   }
  //  MLOG * mlog = static_cast<MLOG*>(PIN_GetThreadData(mlog_key, tid));
    
//	VirtAddrType *buffer_start = static_cast<VirtAddrType*>(buffer);
/*	try {
		GetLock(&lock, tid+1);	// accessing the core and the underlying
								// shared page table is a crirical code section.
		for (UINT64 i=0 ; i<numElements ; ++i) {
			if (buffer_start[i] == WARMUP_TO_RECORD_LOG) {
				++(mlog->sample_count);
				mlog->core.ResetCounters();
				continue;
			} else if (buffer_start[i] == RECORD_TO_WARMUP_LOG) {
				PrintReport(mlog);
				continue;
			}			
			// Record memory access in the core
			mlog->core.RecordMemoryAccess(buffer_start[i]);
		}
		ReleaseLock(&lock);
	} catch (const std::exception& e) {
		mlog->output_file << "Unsuccessful termination, we caught an exception:\n";
		mlog->output_file << e.what() << std::endl;
    	throw e;
	}*/

 //  for (UINT64 i=0 ; i<numElements ; ++i) {
   //   cout<<buffer[i]<<" ";
//}
//cout<<endl;

	return buffer;
}

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
// Pin calls this function every time a new basic block is encountered
VOID Trace(TRACE trace, VOID *v) {
    ostringstream ss;
    if(xx)
    {
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
         filename<<"namd_r_pin_1.txt";
         fcnt++;
         ofstream opfile(filename.str().c_str());
         xx = 0;
         ss<<"/bin/cat /proc/"<<getpid()<<"/maps";
         cout<<ss.str()<<endl;
         //system(ss.str().c_str());
         FILE* opp = popen(ss.str().c_str(),"r");
         char* line = NULL;
         size_t len = 0;
         ssize_t read;
        // char buff[255];
       //  while(fgets(buff, 255, (FILE*) opp))
         while((read = getline(&line, &len, opp)) != -1)
         {
            opfile<<line;
         }
     
    }          

    xx = 0;
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

int fcnt = 2;
/* ===================================================================== */
/* Syscalls Callbacks                                                    */
/* ===================================================================== */
VOID SyscallEntry(THREADID tid, CONTEXT *ctxt, SYSCALL_STANDARD std, VOID *v) {
/*    MLOG * mlog = static_cast<MLOG*>(PIN_GetThreadData(mlog_key, tid));*/
	auto syscall_num = PIN_GetSyscallNumber(ctxt, std);
  // cout<<"syscall "<<syscall_num<<endl;
	if (((syscall_num >= 9) && (syscall_num <= 12)) || (syscall_num == 25)) {
         ostringstream ss;
         stringstream filename;
         filename<<"namd_r_pin_"<<fcnt<<".txt";
         fcnt++;
         ofstream opfile(filename.str().c_str());
         xx = 0;
         ss<<"/bin/cat /proc/"<<getpid()<<"/maps";
     //    cout<<ss.str()<<endl;
         //system(ss.str().c_str());
         FILE* opp = popen(ss.str().c_str(),"r");
         char* line = NULL;
         size_t len = 0;
         ssize_t read;
        // char buff[255];
       //  while(fgets(buff, 255, (FILE*) opp))
         while((read = getline(&line, &len, opp)) != -1)
         {
            opfile<<line;
         }
               
    }
}

VOID SyscallExit(THREADID tid, CONTEXT *ctxt, SYSCALL_STANDARD std, VOID *v) {
/*    MLOG* mlog = static_cast<MLOG*>(PIN_GetThreadData(mlog_key, tid));
	if ((mlog->syscall_num == SYS_mmap) || (mlog->syscall_num == SYS_munmap)) {
	   	UINT64 addr = mlog->syscall_arg0;
	   	if (mlog->syscall_num == SYS_mmap)
	   		// mmap syscall returns the address where space is allocated
	   		addr = PIN_GetSyscallReturn(ctxt, std);
	   	UINT64 length = mlog->syscall_arg1;
	   	
	   	GetLock(&lock, tid+1);	// the page table is shared between all threads.
	   	if (mlog->syscall_num == SYS_mmap) {
	   		page_table.AddMapping(addr, length);
	   	} else if (mlog->syscall_num == SYS_munmap) {
	   		page_table.RemoveMapping(addr, length);
	   	}
	   	ReleaseLock(&lock);
    }*/
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
	// assert that the two types for virtual addresses are the same:
	// VirtAddrType	-	defined at Source/Common/Common.h
	// ADDRINT		-	defined at pin.H
//a	assert((bool)(std::is_same<VirtAddrType, ADDRINT>::value));
	
    // Initialize the pin lock
   // InitLock(&lock);

    // Initialize pin
    if (PIN_Init(argc, argv)) return Usage();

	detach_limit = KnobDetachLimit.Value();

   cout<<"Obtained detach limit value: "<<detach_limit<<endl;
	sample_block_log2 = KnobSampleBlockLog2.Value();
	sample_rate = KnobSampleRate.Value();
    if (sample_rate == 0) std::cerr << "Must use sample rate > 0.\n";

    // Initialize the buffer and set up the callback to process the buffer.
   //cout<<"definetracebuffer "<<num_buffer_pages<<endl;
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
    
    return 0;
}

