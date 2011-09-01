/*
 * S2E Selective Symbolic Execution Framework
 *
 * Copyright (c) 2010, Dependable Systems Laboratory, EPFL
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of the Dependable Systems Laboratory, EPFL nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE DEPENDABLE SYSTEMS LABORATORY, EPFL BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Currently maintained by:
 *    Vitaly Chipounov <vitaly.chipounov@epfl.ch>
 *    Volodymyr Kuznetsov <vova.kuznetsov@epfl.ch>
 *
 * All contributors are listed in S2E-AUTHORS file.
 *
 */

extern "C" {
#include "config.h"
#include "qemu-common.h"
}


#include "BaseInstructions.h"
#include <s2e/S2E.h>
#include <s2e/Database.h>
#include <s2e/S2EExecutor.h>
#include <s2e/S2EExecutionState.h>
#include <s2e/ConfigFile.h>
#include <s2e/Utils.h>

#include <iostream>
#include <sstream>

#include <sys/times.h>
#include <time.h>
#include <unistd.h>


#include <llvm/System/TimeValue.h>
#include <klee/Searcher.h>
#include <klee/Solver.h>
/*
bool my_sort123(const std::pair<uint32_t,uint32_t> a,const std::pair<uint32_t,uint32_t> b)
{ 
  return a.second > b.second;
}
*/
namespace s2e {
namespace plugins {

using namespace std;
using namespace klee;

S2E_DEFINE_PLUGIN(BaseInstructions, "Default set of custom instructions plugin", "",);

void BaseInstructions::initialize()
{
    tainted_value = s2e()->getConfig()->getInt(getConfigKey() + ".tainted_value");
    open = s2e()->getConfig()->getBool(getConfigKey() + ".open");
    exclude = s2e()->getConfig()->getIntegerList(getConfigKey() + ".exclude");

    //printf("open = %d\n",open);

   for(unsigned int i = 0 ; i<exclude.size() ; i++)
      printf("%u\n",exclude[i]);

/*
printf("%x\n",tainted_value & 0x000000ff);i
printf("%x\n",(tainted_value & 0x0000ff00) >> 8);
printf("%x\n",(tainted_value & 0x00ff0000) >> 16);
printf("%x\n",(tainted_value & 0xff000000) >> 24);
*/
    s2e()->getCorePlugin()->onCustomInstruction.connect(
            sigc::mem_fun(*this, &BaseInstructions::onCustomInstruction));

}

/** Handle s2e_op instruction. Instructions:
    0f 3f XX XX XX XX XX XX XX XX
    XX: opcode
 */
void BaseInstructions::handleBuiltInOps(S2EExecutionState* state, uint64_t opcode)
{
    switch((opcode>>8) & 0xFF) {
        case 0: { /* s2e_check */
                uint32_t v = 1;
                state->writeCpuRegisterConcrete(CPU_OFFSET(regs[R_EAX]), &v, 4);
            }
            break;
        case 1: state->enableSymbolicExecution(); break;
        case 2: state->disableSymbolicExecution(); break;

        case 3: { /* make_symbolic */
            uint32_t address, size, name; // XXX
            uint32_t knownLength;
            bool ok = true;

            state->start = times(&(state->t_start));

            ok &= state->readCpuRegisterConcrete(CPU_OFFSET(regs[R_EAX]),
                                                 &address, 4);
            ok &= state->readCpuRegisterConcrete(CPU_OFFSET(regs[R_EBX]),
                                                 &size, 4);
            ok &= state->readCpuRegisterConcrete(CPU_OFFSET(regs[R_ECX]),
                                                 &name, 4);
            ok &= state->readCpuRegisterConcrete(CPU_OFFSET(regs[R_EDX]),
                                                 &knownLength, 4);

            if(!ok) {
                s2e()->getWarningsStream(state)
                    << "ERROR: symbolic argument was passed to s2e_op "
                       " insert_symbolic opcode" << std::endl;
                break;
            }

            std::string nameStr;
            if(!name || !state->readString(name, nameStr)) {
                s2e()->getWarningsStream(state)
                        << "Error reading string from the guest"
                        << std::endl;
                nameStr = "defstr";
            }

//size = 2048;

            s2e()->getMessagesStream(state)
                    << "Inserting symbolic data at " << hexval(address)
                    << " of size " << hexval(size)
                    << " with name '" << nameStr << "'" << std::endl;
//address++;
//s2e()->getMessagesStream(state) << "HOst : " << std::hex << state->getHostAddress(address) << std::endl;
//size--;
            vector<ref<Expr> > symb = state->createSymbolicArray(size, nameStr);
            for(unsigned i = 0; i < size; ++i) {
                if(!state->writeMemory8(address + i, symb[i])) {
                    s2e()->getWarningsStream(state)
                        << "Can not insert symbolic value"
                        << " at " << hexval(address + i)
                        << ": can not write to memory" << std::endl;
                }
//state->constraints.concolicSize = size;
                if(s2e()->getExecutor()->getConcolicMode())
                {
                  klee::ObjectPair op;
                  uint64_t hostAddress =  state->getHostAddress(address+i);
                  if(hostAddress !=  (uint64_t) -1)
                  {
                    op = state->addressSpace.findObject(hostAddress & S2E_RAM_OBJECT_MASK);
                    //s2e()->getMessagesStream(state) << "concrete value: " << op.second->concreteStore[hostAddress & ~S2E_RAM_OBJECT_MASK] << std::endl;          
                    //state->addConstraint( EqExpr::create(symb[i], ConstantExpr::alloc(op.second->concreteStore[hostAddress & ~S2E_RAM_OBJECT_MASK],Expr::Int8)));
                    state->constraints.addConcolicConstraints( EqExpr::create(symb[i], ConstantExpr::create(op.second->concreteStore[hostAddress & ~S2E_RAM_OBJECT_MASK],Expr::Int8)) );
                    //state->constraints.concolicSize++;
                    //state->constraints.setConcolicSize(state->constraints.getConcolicSize() + 1);
                    //s2e()->getWarningsStream(state) << "concolicSize: " <<state->constraints.getConcolicSize() << std::endl; 
                    state->constraints.addNoZeroConstraints( NeExpr::create(ConstantExpr::alloc(0x0, Expr::Int8), symb[i] ));
                  }
                }
    
               else if( i < knownLength)
               {
                 //klee::ref<klee::Expr> all = klee::ConstantExpr::create(0x1,klee::Expr::Bool);
                 for(unsigned int j = 0 ; j<exclude.size() ; j++)
                 {
                   state->addConstraint( NotExpr::create(EqExpr::create(symb[i], ConstantExpr::alloc(exclude[j],Expr::Int8))));
                   //klee::ref<klee::Expr> one_byte= NotExpr::create(EqExpr::create(symb[i], ConstantExpr::alloc(exclude[j],Expr::Int8)));
                   //all = klee::AndExpr::create(all, one_byte);
                 }
                 //state->addConstraint(all);
               }

               //if(i==0)
               //  state->addConstraint( EqExpr::create(symb[i], ConstantExpr::alloc(0x2f,Expr::Int8)));
               //else if(i != size -1) 
               //  state->addConstraint( NotExpr::create(EqExpr::create(symb[i], ConstantExpr::alloc(0x2f,Expr::Int8))));
               //else
               //  state->addConstraint( EqExpr::create(symb[i], ConstantExpr::alloc(0x0,Expr::Int8)));
            }
               //  state->addConstraint( EqExpr::create(symb[size-1], ConstantExpr::alloc(0x0,Expr::Int8)));
             //enum AddresstType addressType = VirtualAddress;
            //int64_t hostAddress =  state->getHostAddress(address-1);
/*
klee::ref<klee::Expr> one_byte =  klee::EqExpr::create( symb[0], klee::ConstantExpr::alloc(0x0 ,klee::Expr::Int8));
bool res;                                                                                                                    
//klee::Solver::Validity res;                                                                                                  
klee::Query query(state->constraints, one_byte);                                                                                             
s2e()->getExecutor()->getSolver()->mayBeTrue(query, res);                                                                    
                                                                                                                               
s2e()->getMessagesStream(state) << symb[0] << " res : " << res << std::endl;                                                             
*/

//s2e()->getWarningsStream(state) << "concolicSize: " << state->constraints.concolicSize << std::endl;

//state->dumpStack(40,state->getSp());

//ObjectPair op;  
//bool success;   
//state->addressSpace.resolveOne(state, s2e()->getExecutor()->getSolver(), symb[0], op, success);
//char ttt;
//const MemoryObject *mo = op.first;
/*
int64_t hostAddress4 =  state->getHostAddress(state->getSp());

if(hostAddress4 !=  (uint64_t) -1)
{
  klee::ObjectPair op4 = state->addressSpace.findObject(hostAddress4 & S2E_RAM_OBJECT_MASK);
  //!op4.second->isByteConcrete(hostAddress4 & ~S2E_RAM_OBJECT_MASK)
  s2e()->getMessagesStream(state) << "size " << op4.second->size<< "ALL: "<<op4.second->isAllConcrete() << std::endl;
   s2e()->getMessagesStream(state) << "offset " << (hostAddress4 & ~S2E_RAM_OBJECT_MASK) << std::endl;
  state->dumpStack(op4.second->size,state->getSp());
}
*/

/*


  std::vector<std::pair<uint32_t,uint32_t> > sym_table;

  uint32_t virtualAddress = state->getSp();

  for(int i=0 ; i<5 ; i++)
  { 
    uint64_t hostAddress =  state->getHostAddress(virtualAddress);
    if(hostAddress !=  (uint64_t) -1)
    {
      klee::ObjectPair op = state->addressSpace.findObject(hostAddress & S2E_RAM_OBJECT_MASK);
      s2e()->getMessagesStream(state) << "size " << op.second->size<< " ALL Concrete?: "<<op.second->isAllConcrete() << " offset " << (hostAddress & ~S2E_RAM_OBJECT_MASK) << std::hex << " address " << virtualAddress - (hostAddress & ~S2E_RAM_OBJECT_MASK) << " ~ "<< virtualAddress + (op.second->size - (hostAddress & ~S2E_RAM_OBJECT_MASK)) - 1<< std::endl;

      unsigned int size = op.second->size;
      unsigned int offset = (hostAddress & ~S2E_RAM_OBJECT_MASK);
      virtualAddress = virtualAddress - offset;
        
      if(! op.second->isAllConcrete())
      {
        state->dumpStack(size/4,virtualAddress);

        for(unsigned int j=0 ; j<size ; j++)
        {   
          if(op.second->isByteKnownSymbolic(j))
          {
            s2e()->getMessagesStream(state) << "1.symbolic address: " << std::hex << virtualAddress + j << " " << state->readMemory8(virtualAddress + j) << std::endl;
            
            int k=1;
            for(j=j+1; j<size ;j++)
            {   
              if(! op.second->isByteKnownSymbolic(j))
              {
                break;
              }
              k++;
              s2e()->getMessagesStream(state) << "2.symbolic address: " << std::hex << virtualAddress + j << " " << state->readMemory8(virtualAddress + j) << std::endl;
            }
           
            if(!sym_table.empty() && (sym_table.back().first + sym_table.back().second) == (virtualAddress + j) - k )
            {
              sym_table.back().second += k;
            } 
            else
            {
              std::pair<uint32_t, uint32_t> temp((virtualAddress + j) - k, k);
              sym_table.push_back(temp);
            }
          }
        }
      } 
      virtualAddress = virtualAddress + size ;
    }
  }

std::vector<std::pair<uint32_t,uint32_t> >::iterator aa = sym_table.begin();
std::vector<std::pair<uint32_t,uint32_t> >::iterator bb = sym_table.end();

//sort(aa, bb, my_sort123);
//my_sort(aa,bb);

  for(std::vector<std::pair<uint32_t,uint32_t> >::iterator it = sym_table.begin() ;  it != sym_table.end() ; it++)
{
      s2e()->getMessagesStream(state) << "3.symbolic address: " << std::hex << it->first << " size: " << it->second << std::endl; 
}


*/






//s2e()->getMessagesStream(state) << "conere??  " << state->getSymbolicRegistersMask() << std::endl;
//printf("concret??????????????? %d\n",s2e()->getExecutor()->isRamSharedConcrete(state,state->getHostAddress(address-5)));
   

//ObjectPair op = state->addressSpace.findObject(hostAddress & S2E_RAM_OBJECT_MASK);  

//s2e()->getMessagesStream(state) << "okok "<<op.second->isByteConcrete(hostAddress & ~S2E_RAM_OBJECT_MASK) << std::endl;
//s2e()->getMessagesStream(state)  << "symbolic???? " << op.first->isSharedConcrete << std::endl;
//op.second.isByteConcrete(address);         

 //const Array *array = new Array(nameStr, size);
            //UpdateList ul(array, 0);
          
//state->addConstraint( klee::EqExpr::create(symb[12], klee::ConstantExpr::alloc(0xff,klee::Expr::Int8)));            
                //state->addConstraint( EqExpr::create(symb[0], ConstantExpr::alloc(tainted_value & 0x000000ff,Expr::Int8)));
                //state->addConstraint( EqExpr::create(symb[1], ConstantExpr::alloc((tainted_value & 0x0000ff00) >> 8,Expr::Int8)));
                //state->addConstraint( EqExpr::create(symb[2], ConstantExpr::alloc((tainted_value & 0x00ff0000) >> 16,Expr::Int8)));
                //state->addConstraint( EqExpr::create(symb[3], ConstantExpr::alloc((tainted_value & 0xff000000) >> 24,Expr::Int8)));
            //s2e()->getWarningsStream(state) << "readexpr : " << ReadExpr::create(ul,ConstantExpr::alloc(0,Expr::Int32)) << endl;
 //state->dumpX86State(s2e()->getWarningsStream());

//uint32_t bp_value;
 //state->readMemoryConcrete(state->getBp(), &bp_value, 4);
// s2e()->getWarningsStream() << "ESP:  " << state->getSp() << std::endl;
// state->dumpStack(128,state->getSp());
              //state->dumpStack(20, state->getSp());
//uint64_t ret;
//state->getReturnAddress(&ret);
// state->readMemoryConcrete(ret, &ret, 4);
//printf("???? %x   \n",bp_value);
            if(open == true)
            {
              uint64_t bp_value;
              //state->getReturnAddress(&rett);

              state->readMemoryConcrete(state->getBp(), &bp_value, 4);
              //printf("=== Pc = %p , Bp = %p , addreee = %p, target=%p, dis=%d\n", state->getPc(), state->getBp(), address, address+12 ,address-bp_value);
              state->dumpStack(20, state->getSp());
              int dis = bp_value - address;
              if(size >= dis + 8 )
              {
                state->addConstraint( klee::EqExpr::create(state->readMemory8(bp_value+4), klee::ConstantExpr::alloc(0x8048424 & 0x000000ff,klee::Expr::Int8)));
                state->addConstraint( klee::EqExpr::create(state->readMemory8(bp_value+5), klee::ConstantExpr::alloc((0x8048424 & 0x0000ff00) >> 8,klee::Expr::Int8)));
state->addConstraint( klee::EqExpr::create(state->readMemory8(bp_value+6), klee::ConstantExpr::alloc((0x8048424 & 0x00ff0000) >> 16,klee::Expr::Int8)));
state->addConstraint( klee::EqExpr::create(state->readMemory8(bp_value+7), klee::ConstantExpr::alloc((0x8048424 & 0xff000000) >> 24,klee::Expr::Int8)));
                //state->addConstraint( EqExpr::create(symb[dis+4], ConstantExpr::alloc(tainted_value & 0x000000ff,Expr::Int8)));
                //state->addConstraint( EqExpr::create(symb[dis+5], ConstantExpr::alloc((tainted_value & 0x0000ff00) >> 8,Expr::Int8)));
                //state->addConstraint( EqExpr::create(symb[dis+6], ConstantExpr::alloc((tainted_value & 0x00ff0000) >> 16,Expr::Int8)));
                //state->addConstraint( EqExpr::create(symb[dis+7], ConstantExpr::alloc((tainted_value & 0xff000000) >> 24,Expr::Int8)));
                //state->addConstraint( EqExpr::create(ConcatExpr::create4(symb[3],symb[2],symb[1],symb[0]), ConstantExpr::alloc(99,Expr::Int32)));
              }
            }
            break;
        }

        case 5:
            {
             
                //Get current path
                state->writeCpuRegister(offsetof(CPUX86State, regs[R_EAX]),
                    klee::ConstantExpr::create(state->getID(), klee::Expr::Int32));
                break;
             
              /*
              uint32_t address, size;
              //uint32_t target;

              bool ok = true;
              ok &= state->readCpuRegisterConcrete(CPU_OFFSET(regs[R_EAX]),
                                     &address, 4);
              ok &= state->readCpuRegisterConcrete(CPU_OFFSET(regs[R_EBX]),
                                     &size, 4);
              //ok &= state->readCpuRegisterConcrete(CPU_OFFSET(regs[R_ECX]),
              //                       &target, 4);

              if(!ok) {
                s2e()->getWarningsStream(state)
                  << "ERROR: symbolic argument was passed to s2e_op "
                  " get_example opcode" << std::endl;
                break;
              }
 
              for(unsigned int i=0 ; i < size ; i++)
              {
                uint64_t hostAddress =  state->getHostAddress(address + i);
                if(hostAddress !=  (uint64_t) -1)
                {
                  ObjectPair op = state->addressSpace.findObject(hostAddress & S2E_RAM_OBJECT_MASK);
                  unsigned int offset = (hostAddress & ~S2E_RAM_OBJECT_MASK);
                  klee::ObjectState *wos = state->addressSpace.getWriteable(op.first, op.second);
                  wos->markByteSymbolic(offset);
                  wos->markByteUnflushed(offset);
                  //op.second->concreteMask[offset] = 0;
                }
              }*/
              break;
            }

        case 6:
            {
                std::string message;
                uint32_t messagePtr;
                bool ok = true;
                klee::ref<klee::Expr> status = state->readCpuRegister(CPU_OFFSET(regs[R_EAX]), klee::Expr::Int32);
                ok &= state->readCpuRegisterConcrete(CPU_OFFSET(regs[R_EBX]), &messagePtr, 4);

//if(s2e()->getExecutor()->getConcolicMode())
//{
//state->constraints.erase(state->constraints.getConcolicSize());
//state->constraints.setConcolicSize(0);
//}
                if (!ok) {
                    s2e()->getWarningsStream(state)
                        << "ERROR: symbolic argument was passed to s2e_op kill state "
                        << std::endl;
                } else {
                    message="<NO MESSAGE>";
                    if(messagePtr && !state->readString(messagePtr, message)) {
                        s2e()->getWarningsStream(state)
                            << "Error reading file name string from the guest" << std::endl;
                    }
                }


//                s2e()->getWarningsStream(state) << "CC : " << state->constraints.getConcolicConstraints() << std::endl;

//                std::vector< ref<Expr> >::const_iterator it = state->constraints.begin();
//                for(; it != state->constraints.end() ;it++)
//                {
//                  s2e()->getWarningsStream(state) << "constraint : " << *it << std::endl;
//                }


                //Kill the current state
                s2e()->getMessagesStream(state) << "Killing state "  << state->getID() << std::endl;
                std::ostringstream os;
                os << "State was terminated by opcode\n"
                   << "            message: \"" << message << "\"\n"
                   << "            status: " << status;
                s2e()->getExecutor()->terminateStateEarly(*state, os.str());
                break;
            }

        case 7:
            {
                //Print the expression
                uint32_t name; //xxx
                bool ok = true;
                ref<Expr> val = state->readCpuRegister(offsetof(CPUX86State, regs[R_EAX]), klee::Expr::Int32);
                ok &= state->readCpuRegisterConcrete(CPU_OFFSET(regs[R_ECX]),
                                                     &name, 4);

                if(!ok) {
                    s2e()->getWarningsStream(state)
                        << "ERROR: symbolic argument was passed to s2e_op "
                           "print_expression opcode" << std::endl;
                    break;
                }

                std::string nameStr = "defstring";
                if(!name || !state->readString(name, nameStr)) {
                    s2e()->getWarningsStream(state)
                            << "Error reading string from the guest"
                            << std::endl;
                }


                s2e()->getMessagesStream() << "SymbExpression " << nameStr << " - "
                        <<val << std::endl;
                break;
            }

        case 8:
            {
                //Print memory contents
                uint32_t address, size, name; // XXX should account for 64 bits archs
                bool ok = true;
                ok &= state->readCpuRegisterConcrete(CPU_OFFSET(regs[R_EAX]),
                                                     &address, 4);
                ok &= state->readCpuRegisterConcrete(CPU_OFFSET(regs[R_EBX]),
                                                     &size, 4);
                ok &= state->readCpuRegisterConcrete(CPU_OFFSET(regs[R_ECX]),
                                                     &name, 4);

                if(!ok) {
                    s2e()->getWarningsStream(state)
                        << "ERROR: symbolic argument was passed to s2e_op "
                           "print_expression opcode" << std::endl;
                    break;
                }

                std::string nameStr = "defstring";
                if(!name || !state->readString(name, nameStr)) {
                    s2e()->getWarningsStream(state)
                            << "Error reading string from the guest"
                            << std::endl;
                }

                s2e()->getMessagesStream() << "Symbolic memory dump of " << nameStr << std::endl;

                for (uint32_t i=0; i<size; ++i) {

                    s2e()->getMessagesStream() << std::hex << "0x" << std::setw(8) << (address+i) << ": " << std::dec;
                    ref<Expr> res = state->readMemory8(address+i);
                    if (res.isNull()) {
                        s2e()->getMessagesStream() << "Invalid pointer" << std::endl;
                    }else {
                        s2e()->getMessagesStream() << res << std::endl;
                    }
                }

                state->dumpX86State(s2e()->getWarningsStream());
                break;
            }

        case 9: state->enableForking(); break;
        case 10: state->disableForking(); break;


        case 0x10: { /* print message */
            uint32_t address; //XXX
            bool ok = state->readCpuRegisterConcrete(CPU_OFFSET(regs[R_EAX]),
                                                        &address, 4);
            if(!ok) {
                s2e()->getWarningsStream(state)
                    << "ERROR: symbolic argument was passed to s2e_op "
                       " message opcode" << std::endl;
                break;
            }

            std::string str="";
            if(!state->readString(address, str)) {
                s2e()->getWarningsStream(state)
                        << "Error reading string message from the guest at address 0x"
                        << std::hex << address
                        << std::endl;
            } else {
                ostream *stream;
                if(opcode >> 16)
                    stream = &s2e()->getWarningsStream(state);
                else
                    stream = &s2e()->getMessagesStream(state);
                (*stream) << "Message from guest (0x" << std::hex << address <<
                        "): " <<  str << std::endl;
            }
            break;
        }

        case 0x20: /* concretize */
        case 0x21: { /* replace an expression by one concrete example */
            uint32_t address, size;
            //uint32_t target;

            bool ok = true;
            ok &= state->readCpuRegisterConcrete(CPU_OFFSET(regs[R_EAX]),
                                                 &address, 4);
            ok &= state->readCpuRegisterConcrete(CPU_OFFSET(regs[R_EBX]),
                                                 &size, 4);
            //ok &= state->readCpuRegisterConcrete(CPU_OFFSET(regs[R_ECX]),
            //                                     &target, 4);

            if(!ok) {
                s2e()->getWarningsStream(state)
                    << "ERROR: symbolic argument was passed to s2e_op "
                       " get_example opcode" << std::endl;
                break;
            }
//ExecutionState temp(state->constraints.getConstraints());
//S2EExecutionState *temp_ptr;
//temp_ptr = &temp;
//temp.addConstraint(state->constraints.getConcolicConstraints());
//state = &temp;
            for(unsigned i = 0; i < size; ++i) {
                ref<Expr> expr = state->readMemory8(address + i);
                if(!expr.isNull()) {
                    if(((opcode>>8) & 0xFF) == 0x20) /* concretize */
                        expr = s2e()->getExecutor()->toConstant(*state, expr, "request from guest");
                    else /* example */
                        expr = s2e()->getExecutor()->toConstantSilent(*state, expr);
                    if(!state->writeMemory(address + i, expr)) {
                    //if(!state->writeMemory(address + i, expr)) {
                        s2e()->getWarningsStream(state)
                            << "Can not write to memory"
                            << " at " << hexval(address + i) << std::endl;
                    }
                } else {
                    s2e()->getWarningsStream(state)
                        << "Can not read from memory"
                        << " at " << hexval(address + i) << std::endl;
                }
            }

            break;
        }

        case 0x50: { /* disable/enable timer interrupt */
            uint64_t disabled = opcode >> 16;
            if(disabled)
                s2e()->getMessagesStream(state) << "Disabling timer interrupt" << std::endl;
            else
                s2e()->getMessagesStream(state) << "Enabling timer interrupt" << std::endl;
            state->writeCpuState(CPU_OFFSET(timer_interrupt_disabled),
                                 disabled, 8);
            break;
        }
        case 0x51: { /* disable/enable all apic interrupts */
            uint64_t disabled = opcode >> 16;
            if(disabled)
                s2e()->getMessagesStream(state) << "Disabling all apic interrupt" << std::endl;
            else
                s2e()->getMessagesStream(state) << "Enabling all apic interrupt" << std::endl;
            state->writeCpuState(CPU_OFFSET(all_apic_interrupts_disabled),
                                 disabled, 8);
            break;
        }

        case 0x52: { /* Gets the current S2E memory object size (in power of 2) */
                uint32_t size = S2E_RAM_OBJECT_BITS;
                state->writeCpuRegisterConcrete(CPU_OFFSET(regs[R_EAX]), &size, 4);
                break;
        }

        case 0x70: /* merge point */
            s2e()->getExecutor()->jumpToSymbolicCpp(state);
            s2e()->getExecutor()->queueStateForMerge(state);
            break;

    default:
            s2e()->getWarningsStream(state)
                << "BaseInstructions: Invalid built-in opcode " << hexval(opcode) << std::endl;
            break;
    }
}

void BaseInstructions::onCustomInstruction(S2EExecutionState* state, 
        uint64_t opcode)
{
    uint8_t opc = (opcode>>8) & 0xFF;
    if (opc <= 0x70) {
        handleBuiltInOps(state, opcode);
    }
}

}
}
