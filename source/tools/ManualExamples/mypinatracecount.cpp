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
#include<string>
#include <sstream>
#include <iostream>

using namespace std;
KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool","o", "PintoolResults.out", "specify output file name");

ofstream trace1;
//FILE * trace;

uint64_t memcount = 0;
// Print a memory read record
VOID RecordMemRead(VOID * ip, VOID * addr)
{
   memcount++;
  // cout<<memcount<<";";
 //   fprintf(trace,"%p: R %p\n", ip, addr);
    //fprintf(trace,"%p\n", (unsigned long)addr, addr);
 //   trace1<<hex<<setfill('0')<<setw(16)<<addr<<endl;
}

// Print a memory write record
VOID RecordMemWrite(VOID * ip, VOID * addr)
{
   memcount++;
  // cout<<memcount<<";";
  //  fprintf(trace,"%p: W %p\n", ip, addr);
    //fprintf(trace,"%p\n", (unsigned long)addr, addr);
   // trace1<<hex<<setfill('0')<<setw(16)<<addr<<endl;
}
//int vma_cnt = 1;
vector<uint64_t> allcounts;
uint64_t inscount = 0;
uint64_t samplecount = 0;
void docount()
{
   inscount++;
   samplecount = inscount%(1ul<<17); 
  // cout<<inscount<<"  "<<samplecount<<";";
}

ADDRINT PIN_FAST_ANALYSIS_CALL IsRecord()
{
  // cout<<"samp = "<<samplecount<<" ret "<<(samplecount == 5)<<";";
  return (samplecount == 5);
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
    UINT32 memOperands = INS_MemoryOperandCount(ins);
   INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)docount, IARG_CALL_ORDER, CALL_ORDER_DEFAULT, IARG_END);

   INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)IsRecord,  IARG_CALL_ORDER, CALL_ORDER_DEFAULT + 10,IARG_END);
   INS_InsertThenCall(ins, IPOINT_BEFORE, (AFUNPTR)InsertMem,  IARG_CALL_ORDER, CALL_ORDER_DEFAULT + 10,IARG_END);

   
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

    // Iterate over each memory operand of the instruction.
    for (UINT32 memOp = 0; memOp < memOperands; memOp++)
    {
        if (INS_MemoryOperandIsRead(ins, memOp))
        {
            INS_InsertPredicatedCall(
                ins, IPOINT_BEFORE, (AFUNPTR)RecordMemRead, IARG_CALL_ORDER, CALL_ORDER_DEFAULT + 20,
                IARG_INST_PTR,
                IARG_MEMORYOP_EA, memOp,
                IARG_END);
        }
        // Note that in some architectures a single memory operand can be 
        // both read and written (for instance incl (%eax) on IA-32)
        // In that case we instrument it once for read and once for write.
        if (INS_MemoryOperandIsWritten(ins, memOp))
        {
            INS_InsertPredicatedCall(
                ins, IPOINT_BEFORE, (AFUNPTR)RecordMemWrite, IARG_CALL_ORDER, CALL_ORDER_DEFAULT + 20,
                IARG_INST_PTR,
                IARG_MEMORYOP_EA, memOp,
                IARG_END);
        }
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
