/*
 * Copyright 2002-2020 Intel Corporation.
 * 
 * This software is provided to you as Sample Source Code as defined in the accompanying
 * End User License Agreement for the Intel(R) Software Development Products ("Agreement")
 * section 1.L.
 * 
 * This software and the related documents are provided as is, with no express or implied
 * warranties, other than those that are expressly stated in the License.
 */

/*
 *  This file contains an ISA-portable PIN tool for tracing memory accesses.
 */

#include <stdio.h>
#include "pin.H"
#include <fstream>
#include <string>
#include <sstream>
#include <iostream>

#define  WARMUP_TO_RECORD_LOG (ADDRINT)0xdeadbeefdeadbeef 
#define  RECORD_TO_WARMUP_LOG (ADDRINT)0xbeefdeadbeefdead 

using namespace std;
KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool","o", "PintoolResults.out", "specify output file name");

// The ID of the buffer
BUFFER_ID buffer_id;
UINT32 num_buffer_pages = 1ul<<6;

ofstream output_file;

uint64_t memcount = 0;

vector<uint64_t> allcounts;
uint64_t inscount = 0;
uint64_t samplecount = 0;
uint64_t prevsamplecount = 0;

VOID PIN_FAST_ANALYSIS_CALL docount()
{
   inscount++;

   uint64_t samplephase = inscount & ((1ul<<27) - 1);
   samplephase = samplephase >> 17;

   prevsamplecount = samplecount;
   samplecount = samplephase; 
}

ADDRINT PIN_FAST_ANALYSIS_CALL IsSample()
{
   return (samplecount == 0) || (samplecount == 1);
}

ADDRINT PIN_FAST_ANALYSIS_CALL IsRecordToWarmupChange()
{
   return (prevsamplecount == 1) && (samplecount == 2);
}

ADDRINT PIN_FAST_ANALYSIS_CALL IsWarmupToRecordChange()
{
   return (prevsamplecount == 0) && (samplecount == 1);
}

// This will be called when the buffer fills up, or the thread exits.
VOID* BufferFull(BUFFER_ID buffer_id, THREADID tid, const CONTEXT *ctxt,
      VOID *buffer, UINT64 numElements, VOID *v) {

   uint64_t *buffer_start = static_cast<uint64_t*>(buffer);

   for (UINT64 i=0 ; i<numElements ; ++i) {
      output_file<<hex<<setfill('0')<<setw(16)<<buffer_start[i]<<endl;
   }

   return buffer;
}

// Is called for every instruction and instruments reads and writes
VOID Instruction(INS ins, VOID *v)
{
   // Instruments memory accesses using a predicated call, i.e.
   // the instrumentation is called iff the instruction will actually be executed.
   // On the IA-32 and Intel(R) 64 architectures conditional moves and REP 
   // prefixed instructions appear as predicated instructions in Pin.
   INS_InsertCall(ins,
                  IPOINT_BEFORE, (AFUNPTR)docount,
                  IARG_FAST_ANALYSIS_CALL, IARG_END);

   INS_InsertIfCall(ins,
                    IPOINT_BEFORE, (AFUNPTR)IsWarmupToRecordChange,
                    IARG_FAST_ANALYSIS_CALL, IARG_END);
   INS_InsertFillBufferThen(ins,
                           IPOINT_BEFORE, buffer_id,
                           IARG_ADDRINT, WARMUP_TO_RECORD_LOG, 0, 
                           IARG_END);

   INS_InsertIfCall(ins,
                   IPOINT_BEFORE, (AFUNPTR)IsRecordToWarmupChange,
                   IARG_FAST_ANALYSIS_CALL, IARG_END);
   INS_InsertFillBufferThen(ins,
                           IPOINT_BEFORE, buffer_id,
                           IARG_ADDRINT, RECORD_TO_WARMUP_LOG, 0,
                           IARG_END);

   UINT32 memOperands = INS_MemoryOperandCount(ins);
   // Iterate over each memory operand of the instruction.
   for (UINT32 memOp = 0; memOp < memOperands; memOp++)
   {
       // Note that in some architectures a single memory operand can be 
      // both read and written (for instance incl (%eax) on IA-32)
      // In that case we instrument it once for read and once for write.
      if (INS_MemoryOperandIsWritten(ins, memOp))
      {
         INS_InsertIfPredicatedCall(ins,
                                    IPOINT_BEFORE, (AFUNPTR)IsSample,
                                    IARG_FAST_ANALYSIS_CALL, IARG_END);
         INS_InsertFillBufferThen(ins,
                                  IPOINT_BEFORE, buffer_id,
                                  IARG_MEMORYOP_EA, memOp, 0,
                                  IARG_END);
      }

      if (INS_MemoryOperandIsRead(ins, memOp))
      {
         INS_InsertIfPredicatedCall(ins,
                                    IPOINT_BEFORE, (AFUNPTR)IsSample,
                                    IARG_FAST_ANALYSIS_CALL, IARG_END);
         INS_InsertFillBufferThen(ins,
                                  IPOINT_BEFORE, buffer_id,
                                  IARG_MEMORYOP_EA, memOp, 0,
                                  IARG_END);
      }
 }
}

VOID Fini(INT32 code, VOID *v)
{
   output_file.close();
}
/* ===================================================================== */
/* Syscalls Callbacks                                                    */
/* ===================================================================== */

VOID SyscallEntry(THREADID tid, CONTEXT *ctxt, SYSCALL_STANDARD std, VOID *v) {
}

VOID SyscallExit(THREADID tid, CONTEXT *ctxt, SYSCALL_STANDARD std, VOID *v) {
}


/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */

INT32 Usage()
{
   PIN_ERROR( "This Pintool prints a trace of memory addresses\n" 
         + KNOB_BASE::StringKnobSummary() + "\n");
   return -1;
}

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */

int main(int argc, char *argv[])
{
   if (PIN_Init(argc, argv)) return Usage();

   buffer_id = PIN_DefineTraceBuffer(
         sizeof(ADDRINT), num_buffer_pages, BufferFull, 0);

   if(buffer_id == BUFFER_ID_INVALID) {
      std::cerr <<"Error : could not allocate initial buffer."<<std::endl;
      return 1;
   }

   std::string output_file_name = KnobOutputFile.Value() + "-0";
   output_file.open(output_file_name.c_str());

   INS_AddInstrumentFunction(Instruction, 0);
   PIN_AddFiniFunction(Fini, 0);

   // Never returns
   PIN_StartProgram();

   return 0;
}
