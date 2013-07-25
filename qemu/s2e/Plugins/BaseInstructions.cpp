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

#ifdef __MHHUANG_SEND_PID__
extern uint64_t AppPID;
#endif

namespace s2e {
namespace plugins {

using namespace std;
using namespace klee;

S2E_DEFINE_PLUGIN(BaseInstructions, "Default set of custom instructions plugin", "",);

void BaseInstructions::initialize()
{
#ifdef __MHHUANG_MANUAL_ADAPTIVE__
    symbolicOffset = s2e()->getConfig()->getInt(getConfigKey() + ".SymbolicOffset");
    symbolicSize = s2e()->getConfig()->getInt(getConfigKey() + ".SymbolicSize");
    eipOffset = s2e()->getConfig()->getInt(getConfigKey() + ".SymbolicEIPOffset");
    eipSize = s2e()->getConfig()->getInt(getConfigKey() + ".SymbolicEIPSize");
    jmpOffset = s2e()->getConfig()->getInt(getConfigKey() + ".SymbolicJmpOffset");
    jmpSize = s2e()->getConfig()->getInt(getConfigKey() + ".SymbolicJmpSize");
#endif

    //exclude = s2e()->getConfig()->getIntegerList(getConfigKey() + ".exclude");

    //for(unsigned int i = 0 ; i<exclude.size() ; i++)
    //  printf("%d\n",exclude[i]);

    s2e()->getCorePlugin()->onCustomInstruction.connect(
            sigc::mem_fun(*this, &BaseInstructions::onCustomInstruction));

}

void BaseInstructions::handleMhhuangOps(S2EExecutionState* state, uint64_t opcode) {
    switch(opcode) {
#ifdef __MHHUANG_CHECK_SYM_ARG__
        case 4: {   /* mhhuang_check_sym_arg */
            uint32_t address, size, type;
            bool ok = true;

            ok &= state->readCpuRegisterConcrete(CPU_OFFSET(regs[R_EBX]),
                                                 &address, 4);
            ok &= state->readCpuRegisterConcrete(CPU_OFFSET(regs[R_ECX]),
                                                 &size, 4);
            ok &= state->readCpuRegisterConcrete(CPU_OFFSET(regs[R_EDX]),
                                                 &type, 4);

            if (!ok) {
                s2e()->getWarningsStream(state)
                    << "ERROR: symbolic argument was passed to mhhuang_check_sym_arg"
                    << std::endl;
            }

            s2e()->getMessagesStream(state)
                    << "Process " << hexval(*(state->cr3)) << " check symbolic arg"
                    << ", addr " << hexval(address)
                    << ", size " << hexval(size)
                    << ", type " << hexval(type) << std::endl;

            int ret = 0;
            switch(type) {
                case SYM_ARG_MALLOC: {
                    bool isSymbolic = false;
                    ref<Expr> arg(0);
                    for(uint32_t i=0; i<size; i++) {
                        ref<Expr> byte = state->readMemory8(address+i);
                        if(!isa<ConstantExpr>(byte)) {
                            isSymbolic = true;
                        }

                        arg = i ? ConcatExpr::create(byte, arg) : byte;
                    }

                    if(isSymbolic) {
                        s2e()->getMessagesStream(state)
                            << "Process " << hexval(*(state->cr3)) << " get symbolic arg: "
                            << arg
                            << ", type " << hexval(type) << std::endl;
                        ret = 1;
                    }
                    break;
                }
                case SYM_ARG_PRINTF: 
                case SYM_ARG_SYSLOG: {
                    /* Only try to exploit when fmt is located at stack */
                    if(address > 0xbfffffff || address < 0xb0000000) {
                        break;
                    }

                    uint32_t symbolicCount = 0;
                    uint8_t concreteStr[200];
                    uint32_t concreteLen = 0;
                    /* Count the number of symbolic bytes */
                    for(int i=0; ; i++) {
                        ref<Expr> byte = state->readMemory8(address+i);
                        if(byte.get() == NULL)
                            break;

                        ref<klee::ConstantExpr> ce = dyn_cast<klee::ConstantExpr>(byte);
                        if(ce.get() == NULL) {
                            ce = s2e()->getExecutor()->toConstantSilent(*state, byte);
                            symbolicCount++;
                        }

                        uint8_t concreteValue = ce->getZExtValue();
                        if(concreteValue != 0) {
                            if(concreteLen < sizeof(concreteStr)-1) {
                                concreteStr[concreteLen] = concreteValue;
                                concreteLen++;
                            }
                        }
                        else {
                            break;
                        }
                    }
                    concreteStr[concreteLen] = 0;
                    
                    if(symbolicCount > 50) {
                        s2e()->getWarningsStream(state)
                            << "Process " << hexval(*(state->cr3)) << " get symbolic arg"
                            << ", type " << hexval(type)
                            << ", concrete: " << concreteStr << std::endl;
                        ret = 1;
                    }

                    break;
                }
            }

            state->writeCpuRegisterConcrete(CPU_OFFSET(regs[R_EAX]), &ret, 4);
            break;
        }
#endif
        case 0x5: { /* mhhuang_declare_input_range */
            uint32_t address, size;
            bool ok = true;

            ok &= state->readCpuRegisterConcrete(CPU_OFFSET(regs[R_EAX]),
                                                 &address, 4);
            ok &= state->readCpuRegisterConcrete(CPU_OFFSET(regs[R_EBX]),
                                                 &size, 4);
            if (!ok) {
                s2e()->getWarningsStream(state)
                    << "ERROR: symbolic argument was passed to mhhuang_declare_input_range"
                    << std::endl;
            }

            s2e()->getCorePlugin()->onSetInputRange.emit(state, address, size);

            break;
        }
#ifdef __KS_MHHUANG_STATE_FORK__
        case 0xb: { /* mhhuang_state_fork */
            Executor::StatePair states = s2e()->getExecutor()->dummyFork(state);

            S2EExecutionState* oldState = dynamic_cast<S2EExecutionState*>(states.first);
            S2EExecutionState* newState = dynamic_cast<S2EExecutionState*>(states.second);
            assert(oldState && "S2EExecutionState conversion fail");
            assert(newState && "S2EExecutionState conversion fail");

            s2e()->getMessagesStream(state) << "State fork, new state " << newState->getID()  << std::endl;

            uint32_t cid = newState->getID();
            assert(cid != 0 && "ERROR: add handling of the case cid == 0");
            oldState->writeCpuRegisterConcrete(CPU_OFFSET(regs[R_EAX]), &cid, 4);
            cid = 0;
            newState->writeCpuRegisterConcrete(CPU_OFFSET(regs[R_EAX]), &cid, 4);

            break;
        }

        case 0xc: { /* mhhuang_state_wait */
            int res = s2e()->getExecutor()->waitState(state);
            /* If we reach here, it can be two possibilities
               One is the waitState function fail, thus the return value will be -1;
               another is the state is previously waiting and just be waken up, the
               return value will be the exit status of the waited state
             */
            if(res != -1)
                state->writeCpuRegisterConcrete(CPU_OFFSET(regs[R_EAX]), &res, 4);

            break;
        }

        case 0xd: { /* mhhuang_register_true_terminate */
            uint32_t eventID;
            uint32_t eventPara;

            bool ok = true;
            ok &= state->readCpuRegisterConcrete(CPU_OFFSET(regs[R_EAX]), &eventID, 4);
            ok &= state->readCpuRegisterConcrete(CPU_OFFSET(regs[R_EBX]), &eventPara, 4);
            if (!ok) {
                s2e()->getWarningsStream(state)
                    << "ERROR: symbolic argument was passed to mhhuang_register_true_terminate"
                    << std::endl;
            }

            state->addTerminateInfo(eventID, eventPara);
            s2e()->getMessagesStream(state) << "Add terminate info, eventID " << eventID << ", eventPara " << eventPara << std::endl;

            break;
        }

        case 0xe: { /* mhhuang_on_corrupt_fmt */
            uint32_t fmt;
            uint32_t dollarOffset;
            uint32_t wordOffset;

            bool ok = true;
            ok &= state->readCpuRegisterConcrete(CPU_OFFSET(regs[R_EAX]), &fmt, 4);
            ok &= state->readCpuRegisterConcrete(CPU_OFFSET(regs[R_EBX]), &dollarOffset, 4);
            ok &= state->readCpuRegisterConcrete(CPU_OFFSET(regs[R_ECX]), &wordOffset, 4);
            if (!ok) {
                s2e()->getWarningsStream(state)
                    << "ERROR: symbolic argument was passed to mhhuang_on_corrupt_fmt"
                    << std::endl;
            }

            s2e()->getCorePlugin()->onCorruptFmt.emit(state, fmt, dollarOffset, wordOffset);

            break;
        }
#endif
#ifdef __MHHUANG_MANUAL_ADAPTIVE__
        case 0xf: { /* mhhuang_get_conf_symbolic_offset */
            state->writeCpuRegisterConcrete(CPU_OFFSET(regs[R_EAX]), &symbolicOffset, 4);
            break;
        }

        case 0x10: { /* mhhuang_get_conf_symbolic_size */
            state->writeCpuRegisterConcrete(CPU_OFFSET(regs[R_EAX]), &symbolicSize, 4);
            break;
        }

        case 0x11: { /* mhhuang_get_conf_symbolic_eip_offset */
            state->writeCpuRegisterConcrete(CPU_OFFSET(regs[R_EAX]), &eipOffset, 4);
            break;
        }

        case 0x12: { /* mhhuang_get_conf_symbolic_eip_size */
            state->writeCpuRegisterConcrete(CPU_OFFSET(regs[R_EAX]), &eipSize, 4);
            break;
        }

        case 0x13: { /* mhhuang_get_conf_symbolic_jmp_offset */
            state->writeCpuRegisterConcrete(CPU_OFFSET(regs[R_EAX]), &jmpOffset, 4);
            break;
        }

        case 0x14: { /* mhhuang_get_conf_symbolic_jmp_size */
            state->writeCpuRegisterConcrete(CPU_OFFSET(regs[R_EAX]), &jmpSize, 4);
            break;
        }
#endif
        case 0x15: {
            s2e()->getWarningsStream(state) << "Switch to symbolic mode" << std::endl;
            state->isConcolicMode = false;
            break;
        }
#ifdef __MHHUANG_S2E_TRACE_EXEC__
        case 0x55: {
            static ofstream execTrace;

            if(!execTrace.is_open()) {
                execTrace.open("/home/mhhuang/execTrace");
            }

            //if(!state->isRunningConcrete()) {
            //    std::cout << "[xxx] Symbolic execute TB 0x" << std::hex << *(state->eip) << ", CR3 0x" << *(state->cr3) << std::endl;
            //}

            //if(*(state->cr3) == 0x1bff000) {
            //    state->writeCpuState(CPU_OFFSET(timer_interrupt_disabled), 1, 8);

            //    execTrace << "[xxx] Concrete execute TB 0x" << std::hex << *(state->eip) << ", CR3 0x" << *(state->cr3) << std::endl;
            //}

            break;
        }
#endif
    }

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
            bool ok = true;

            state->start = times(&(state->t_start));

            ok &= state->readCpuRegisterConcrete(CPU_OFFSET(regs[R_EAX]),
                                                 &address, 4);
            ok &= state->readCpuRegisterConcrete(CPU_OFFSET(regs[R_EBX]),
                                                 &size, 4);
            ok &= state->readCpuRegisterConcrete(CPU_OFFSET(regs[R_ECX]),
                                                 &name, 4);

            if(!ok) {
                s2e()->getWarningsStream(state)
                    << "ERROR: symbolic argument was passed to s2e_op "
                       " insert_symbolic opcode" << std::endl;
                break;
            }

            if(size == 0) {
                break;
            }

            std::string nameStr;
            if(!name || !state->readString(name, nameStr)) {
                s2e()->getWarningsStream(state)
                        << "Error reading string from the guest"
                        << std::endl;
                nameStr = "defstr";
            }

#ifdef __KS_MHHUANG_SYM_READ__
            if(nameStr.find(KS_PSEUDO_VAR_PREFIX) == 0) {
                assert(false && "Can not using the name with common prefix of pseudo symbolic variables");
            }
#endif

            s2e()->getMessagesStream(state)
                    << "Process " << hexval(*(state->cr3)) << " inserting symbolic data at " << hexval(address)
                    << " of size " << hexval(size)
                    << " with name '" << nameStr << "'" << std::endl;

            s2e()->getCorePlugin()->onSetSymbolicAddr.emit(state, address, nameStr.c_str());

            vector<ref<Expr> > symb = state->createSymbolicArray(size, nameStr);
            for(unsigned i = 0; i < size; ++i) {
                if(!state->writeMemory8(address + i, symb[i])) {
                    s2e()->getWarningsStream(state)
                        << "Can not insert symbolic value"
                        << " at " << hexval(address + i)
                        << ": can not write to memory" << std::endl;
                }

                klee::ObjectPair op;
                uint64_t hostAddress =  state->getHostAddress(address+i);
                if(hostAddress !=  (uint64_t) -1) {
                    op = state->addressSpace.findObject(hostAddress & S2E_RAM_OBJECT_MASK);
                    state->constraints.addConcolicConstraint(EqExpr::create(symb[i], ConstantExpr::create(op.second->concreteStore[hostAddress & ~S2E_RAM_OBJECT_MASK],Expr::Int8)) );
                    state->addConstraint(NeExpr::create(ConstantExpr::alloc(0x0,Expr::Int8),symb[i]));
                }
            }

            break;
        }

        case 4: {
            uint32_t mhhuangOp = ((opcode>>16) & 0xFF);
            handleMhhuangOps(state, mhhuangOp);
            break;
        }

        case 5:
            {
                //Get current path
                state->writeCpuRegister(offsetof(CPUX86State, regs[R_EAX]),
                    klee::ConstantExpr::create(state->getID(), klee::Expr::Int32));
                break;
            }

        case 6: /* Kill state */
            {
                std::string message;
                uint32_t messagePtr;
                int status;
                bool ok = true;
                ok &= state->readCpuRegisterConcrete(CPU_OFFSET(regs[R_EAX]), &status, 4);
                ok &= state->readCpuRegisterConcrete(CPU_OFFSET(regs[R_EBX]), &messagePtr, 4);

                assert(ok && "ERROR: symbolic argument was passed to s2e_op kill state");

                message="<NO MESSAGE>";
                if(messagePtr && !state->readString(messagePtr, message)) {
                    s2e()->getWarningsStream(state)
                        << "Error reading file name string from the guest" << std::endl;
                }

#ifdef __KS_MHHUANG_STATE_FORK__
                s2e()->getExecutor()->wakeWaitingState(state, status);
#endif

                //Kill the current state
                s2e()->getMessagesStream(state) << "Process " << hexval(*(state->cr3)) << " killing state "  << state->getID() << std::endl;
                std::ostringstream os;
                os << "State was terminated by opcode\n"
                   << "            message: \"" << message << "\"\n"
                   << "            status: " << status;

#ifdef __MHHUANG_MEASURE_TIME__
                //state->printAllStat();
                //s2e()->getCorePlugin()->onDumpSymbolicBlocks.emit(state);
#endif

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

#ifdef __MHHUANG_TRACE_POINT__
        case (__MHHUANG_MODE_CALL_FROM_GUEST__>>8): {
#ifdef __MHHUANG_SEND_PID__
                AppPID = state->getPid();
#endif

            /* -mhhuang-delete- */
            if(state->getPc() < 0x4fffffff && state->getPc() > 0x40000000) {
                int aa = 33;
                int bb = aa;
            }

            break;
        }
#endif

        case 0x70: /* merge point */
            s2e()->getExecutor()->jumpToSymbolicCpp(state);
            s2e()->getExecutor()->queueStateForMerge(state);
            break;

    default:
            s2e()->getWarningsStream(state)
                << "BaseInstructions: Invalid built-in opcode " << hexval((opcode>>8) & 0xFF) <<"the eip is "<<state->getPc()<< std::endl;
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
