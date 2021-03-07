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


ofstream trace1;
//FILE * trace;

uint64_t memcount = 0;
// Print a memory read record
VOID RecordMemRead(VOID * ip, VOID * addr)
{
//   memcount++;
  // cout<<memcount<<";";
 //   fprintf(trace,"%p: R %p\n", ip, addr);
    //fprintf(trace,"%p\n", (unsigned long)addr, addr);
    trace1<<hex<<setfill('0')<<setw(16)<<addr<<endl;
}

// Print a memory write record
VOID RecordMemWrite(VOID * ip, VOID * addr)
{
 //  memcount++;
  // cout<<memcount<<";";
  //  fprintf(trace,"%p: W %p\n", ip, addr);
    //fprintf(trace,"%p\n", (unsigned long)addr, addr);
    trace1<<hex<<setfill('0')<<setw(16)<<addr<<endl;
}
//int vma_cnt = 1;
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
  // cout<<inscount<<"  "<<samplecount<<";";
}

ADDRINT PIN_FAST_ANALYSIS_CALL IsRecord()
{
  // cout<<"samp = "<<samplecount<<" ret "<<(samplecount == 5)<<";";
  return (samplecount == 1);
}

ADDRINT PIN_FAST_ANALYSIS_CALL IsSample()
{
  // cout<<"samp = "<<samplecount<<" ret "<<(samplecount == 5)<<";";
  return (samplecount == 0) || (samplecount == 1);
}

ADDRINT PIN_FAST_ANALYSIS_CALL IsRecordToWarmupChange()
{
  // cout<<"samp = "<<samplecount<<" ret "<<(samplecount == 5)<<";";
  return (prevsamplecount == 1) && (samplecount == 2);
}

ADDRINT PIN_FAST_ANALYSIS_CALL IsWarmupToRecordChange()
{
  // cout<<"samp = "<<samplecount<<" ret "<<(samplecount == 5)<<";";
  return (prevsamplecount == 0) && (samplecount == 1);
}

void InsertRecordToWarmup()
{
   trace1<<hex<<RECORD_TO_WARMUP_LOG<<endl;
}

void InsertWarmupToRecord()
{
   trace1<<hex<<WARMUP_TO_RECORD_LOG<<endl;
}

// This will be called when the buffer fills up, or the thread exits.
VOID* BufferFull(BUFFER_ID buffer_id, THREADID tid, const CONTEXT *ctxt,
	VOID *buffer, UINT64 numElements, VOID *v) {
//    MLOG * mlog = static_cast<MLOG*>(PIN_GetThreadData(mlog_key, tid));
    
	//VirtAddrType *buffer_start = static_cast<VirtAddrType*>(buffer);
	uint64_t *buffer_start = static_cast<uint64_t*>(buffer);
	//try
    {
	//	PIN_GetLock(&lock, tid+1);	// accessing the core and the underlying
								// shared page table is a crirical code section.
		for (UINT64 i=0 ; i<numElements ; ++i) {
			if (buffer_start[i] == WARMUP_TO_RECORD_LOG) {
				//++(mlog->sample_count);
            trace1<<hex<<setfill('0')<<setw(16)<<buffer_start[i]<<endl;
				//mlog->core.ResetCounters();
				continue;
			} else if (buffer_start[i] == RECORD_TO_WARMUP_LOG) {
			//	PrintReport(mlog);
            trace1<<hex<<setfill('0')<<setw(16)<<buffer_start[i]<<endl;
				continue;
			}			
			// Record memory access in the core
         //cout<<hex<<buffer_start[i]<<endl;
         trace1<<hex<<setfill('0')<<setw(16)<<buffer_start[i]<<endl;
//			mlog->core.RecordMemoryAccess(buffer_start[i]);
		}
		//PIN_ReleaseLock(&lock);
	}
/* catch (const std::exception& e) {
		mlog->output_file << "Unsuccessful termination, we caught an exception:\n";
		mlog->output_file << e.what() << std::endl;
    	throw e;
	}*/
	return buffer;
}



uint64_t xaxis = 1;
void InsertMem()
{
  // cout<<"reset";
   trace1<<xaxis<<","<<memcount<<endl;
   xaxis++;
   memcount = 0;
}

// Is called for every instruction and instruments reads and writes
VOID Instruction(INS ins, VOID *v)
{
    // Instruments memory accesses using a predicated call, i.e.
    // the instrumentation is called iff the instruction will actually be executed.
    //
    // On the IA-32 and Intel(R) 64 architectures conditional moves and REP 
    // prefixed instructions appear as predicated instructions in Pin.
   INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)docount, IARG_FAST_ANALYSIS_CALL, IARG_END);

  // INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)IsRecord,  IARG_CALL_ORDER, CALL_ORDER_DEFAULT + 10,IARG_END);
 //  INS_InsertThenCall(ins, IPOINT_BEFORE, (AFUNPTR)InsertMem,  IARG_CALL_ORDER, CALL_ORDER_DEFAULT + 10,IARG_END);

   INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)IsWarmupToRecordChange, IARG_FAST_ANALYSIS_CALL, IARG_END);
   INS_InsertFillBufferThen(ins, IPOINT_BEFORE, buffer_id,  IARG_ADDRINT, WARMUP_TO_RECORD_LOG, 0, IARG_END);

   INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)IsRecordToWarmupChange,  IARG_FAST_ANALYSIS_CALL, IARG_END);
   INS_InsertFillBufferThen(ins, IPOINT_BEFORE, buffer_id, IARG_ADDRINT, RECORD_TO_WARMUP_LOG, 0, IARG_END);
/*********************************
		// Log every warmup --> record phase change
       	INS_InsertIfCall(ins, IPOINT_BEFORE,
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


*******************************************/

   
   //cout<<inscount<<endl;
 /*  if(inscount%(1ul<<17) == 0)
   {
      trace1<<memcount<<";";
      allcounts.push_back(memcount);
      memcount = 0;
   }*/
      

 /*  if(vma_cnt == 1)
   {
      ostringstream ss;
      stringstream filename;
      string outputfileval = KnobOutputFile.Value();
      size_t pos = outputfileval.find("/", 72);

      //filename<<KnobOutputFile.Value()<<"/vma_"<<vma_cnt;
      filename<<outputfileval.substr(0,pos)<<"/VMAs/vma_"<<vma_cnt;
      cout<<"writing to "<<filename.str()<<endl;
      trace1<<"vma_"<<dec<<vma_cnt<<endl;
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
*/

    UINT32 memOperands = INS_MemoryOperandCount(ins);
    // Iterate over each memory operand of the instruction.
    for (UINT32 memOp = 0; memOp < memOperands; memOp++)
    {
    //    if (INS_MemoryOperandIsRead(ins, memOp))
        {
            INS_InsertIfPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)IsSample, IARG_FAST_ANALYSIS_CALL, IARG_END);
            INS_InsertFillBufferThen(
                ins, IPOINT_BEFORE, buffer_id, IARG_MEMORYOP_EA, memOp, 0,
                IARG_END);
        }
        // Note that in some architectures a single memory operand can be 
        // both read and written (for instance incl (%eax) on IA-32)
        // In that case we instrument it once for read and once for write.
/*      if (INS_MemoryOperandIsWritten(ins, memOp))
        {
            INS_InsertIfPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)IsSample,  IARG_CALL_ORDER, CALL_ORDER_DEFAULT + 40,IARG_END);
            INS_InsertThenCall(
                ins, IPOINT_BEFORE, (AFUNPTR)RecordMemWrite, IARG_CALL_ORDER, CALL_ORDER_DEFAULT + 40,
                IARG_INST_PTR,
                IARG_MEMORYOP_EA, memOp,
                IARG_END);
        }*/
    }
}

VOID Fini(INT32 code, VOID *v)
{
   // fprintf(trace, "#eof\n");
   // fclose(trace);
      trace1.close();
}
/* ===================================================================== */
/* Syscalls Callbacks                                                    */
/* ===================================================================== */

VOID SyscallEntry(THREADID tid, CONTEXT *ctxt, SYSCALL_STANDARD std, VOID *v) {
    /*MLOG * mlog = static_cast<MLOG*>(PIN_GetThreadData(mlog_key, tid));
   mlog->syscall_num = PIN_GetSyscallNumber(ctxt, std);
   if ((mlog->syscall_num == SYS_mmap) || (mlog->syscall_num == SYS_munmap)) {
       mlog->syscall_arg0 = PIN_GetSyscallArgument(ctxt, std, 0);
       mlog->syscall_arg1 = PIN_GetSyscallArgument(ctxt, std, 1);
    }*/
}

VOID SyscallExit(THREADID tid, CONTEXT *ctxt, SYSCALL_STANDARD std, VOID *v) {
  //  MLOG* mlog = static_cast<MLOG*>(PIN_GetThreadData(mlog_key, tid));

//   UINT64 syscall_num = PIN_GetSyscallNumber(ctxt, std);
//
//   if (((/*mlog->*/syscall_num >= 9) && (/*mlog->*/syscall_num <= 12)) || (/*mlog->*/syscall_num == 25))
//   {
//      ostringstream ss;
//      stringstream filename;
//      string outputfileval = KnobOutputFile.Value();
//      size_t pos = outputfileval.find("/", 72);
//
//     // filename<<KnobOutputFile.Value()<<"/vma_"<<vma_cnt;
//      filename<<outputfileval.substr(0,pos)<<"/VMAs/vma_"<<vma_cnt;
//      trace1<<"vma_"<<dec<<vma_cnt<<endl;
//      vma_cnt++;
//      ofstream opfile(filename.str().c_str());
//      ss<<"/bin/cat /proc/"<<PIN_GetPid()<<"/maps";
//
//      FILE* opp = popen(ss.str().c_str(),"r");
//      char* line = NULL;
//      size_t len = 0;
//      ssize_t read;
//
//      while((read = getline(&line, &len, opp)) != -1)
//      {
//         opfile<<line;
//      }
//   }
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
    //trace = fopen("pinatrace.out", "w");
 std::string output_file_name = KnobOutputFile.Value() + "-0";
    trace1.open(output_file_name.c_str());

//    trace1 <<scientific;
    INS_AddInstrumentFunction(Instruction, 0);
    PIN_AddFiniFunction(Fini, 0);

    // Never returns
    PIN_StartProgram();
    
    return 0;
}
