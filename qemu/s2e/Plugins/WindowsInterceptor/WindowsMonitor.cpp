#include <s2e/s2e.h>
#include <s2e/ConfigFile.h>
#include "WindowsMonitor.h"
#include "UserModeInterceptor.h"

#include <string>
#include <cstring>
#include <iostream>
#include <assert.h>

using namespace std;

using namespace s2e;
using namespace s2e::plugins;

S2E_DEFINE_PLUGIN(WindowsMonitor, "Plugin for monitoring Windows kernel/user-mode events", "Interceptor");

WindowsMonitor::~WindowsMonitor()
{
   if (m_UserModeInterceptor) {
      delete m_UserModeInterceptor;
   }
}

void WindowsMonitor::initialize()
{
   string Version = s2e()->getConfig()->getString(getConfigKey() + ".version");
   m_UserMode = s2e()->getConfig()->getBool(getConfigKey() + ".userMode");
   m_KernelMode = s2e()->getConfig()->getBool(getConfigKey() + ".kernelMode");
   
   //For debug purposes
   m_MonitorModuleLoad = s2e()->getConfig()->getBool(getConfigKey() + ".monitorModuleLoad");
   m_MonitorModuleUnload = s2e()->getConfig()->getBool(getConfigKey() + ".monitorModuleUnload");
   m_MonitorProcessUnload = s2e()->getConfig()->getBool(getConfigKey() + ".monitorProcessUnload");
   
   m_KernelBase = 0x80000000;

   if (!strcasecmp(Version.c_str(), "SP2")) {
      m_Version = WindowsMonitor::SP2;
      m_PointerSize = 4;
   }else if (!strcasecmp(Version.c_str(), "SP3")) {
      m_Version = WindowsMonitor::SP3;
      m_PointerSize = 4;
   }else {
      std::cout << "Unsupported of invalid Windows version " << Version << std::endl;
      exit(-1);
   }

   m_UserModeInterceptor = NULL;
   if (m_UserMode) {
      m_UserModeInterceptor = new WindowsUmInterceptor(this);
   }

   s2e()->getCorePlugin()->onTranslateBlockStart.connect(
      sigc::mem_fun(*this, &WindowsMonitor::slotTranslateBlockStart));
}

void WindowsMonitor::slotTranslateBlockStart(ExecutionSignal *signal, uint64_t pc)
{
   if(m_UserMode) {
      if (pc == GetLdrpCallInitRoutine() && m_MonitorModuleLoad) {
         std::cout << "Basic block for LdrpCallInitRoutine " << std::hex << pc << std::dec << std::endl;
         signal->connect(sigc::mem_fun(*this, &WindowsMonitor::slotUmCatchModuleLoad));
      }else if (pc == GetNtTerminateProcessEProcessPoint() && m_MonitorProcessUnload) {
         std::cout << "Basic block for NtTerminateProcess " << std::hex << pc << std::dec << std::endl;
         signal->connect(sigc::mem_fun(*this, &WindowsMonitor::slotUmCatchProcessTermination));
      }else if (pc == GetDllUnloadPc() && m_MonitorModuleUnload) {
         std::cout << "Basic block for dll unload " << std::hex << pc << std::dec << std::endl;
         signal->connect(sigc::mem_fun(*this, &WindowsMonitor::slotUmCatchModuleUnload));
      }
   }

   if(m_KernelMode) {
      if (pc != CheckDriverLoad(pc)) {
         signal->connect(sigc::mem_fun(*this, &WindowsMonitor::slotKmExecuteBlockStart));
      }
   }
}

void WindowsMonitor::slotUmCatchModuleLoad(S2EExecutionState *state, uint64_t pc)
{
   std::cout << "User mode module load at " << std::hex << pc << std::dec << std::endl;
   m_UserModeInterceptor->CatchModuleLoad(state->getCpuState());
}

void WindowsMonitor::slotUmCatchModuleUnload(S2EExecutionState *state, uint64_t pc)
{
   std::cout << "User mode module unload at " << std::hex << pc << std::dec << std::endl;
   m_UserModeInterceptor->CatchModuleUnload(state->getCpuState());
}

void WindowsMonitor::slotUmCatchProcessTermination(S2EExecutionState *state, uint64_t pc)
{
   std::cout << "Caught process termination" << std::endl;
   m_UserModeInterceptor->CatchProcessTermination(state->getCpuState());
}

void WindowsMonitor::slotKmExecuteBlockStart(S2EExecutionState *state, uint64_t pc)
{
   std::cout << "Kernel mode module load at " << std::hex << pc << std::dec << std::endl;
}

bool WindowsMonitor::CheckDriverLoad(uint64_t eip) const
{
   switch(m_Version) {
    case SP2: return eip >= 0x805A078C && eip <= 0x805A0796;
    case SP3: return eip >= 0x805A3990 && eip <= 0x805A399A;
    default: return false;
   }
   return true;
}

bool WindowsMonitor::CheckPanic(uint64_t eip) const
{
   eip -= m_KernelBase;

   switch(m_Version) {
    case SP2: return eip == 0x0045B7BA  || eip == 0x0045C2DF || eip == 0x0045C303;
    case SP3: return eip == 0x0045BCAA  || eip == 0x0045C7CD || eip == 0x0045C7F3;
    default: return false;
   }
   return true;
}


uint64_t WindowsMonitor::GetUserAddressSpaceSize() const
{
   return 0x80000000;
}

uint64_t WindowsMonitor::GetKernelStart() const
{
   return 0x80000000;
}

uint64_t WindowsMonitor::GetLdrpCallInitRoutine() const
{
   switch(m_Version) {
    case SP2: return 0x7C901193;
    case SP3: return 0x7C901176;
   }
   assert(false && "Unknown OS version\n");
   return 0;
}

unsigned WindowsMonitor::GetPointerSize() const
{
   return m_PointerSize;
}



uint64_t WindowsMonitor::GetNtTerminateProcessEProcessPoint() const
{
   switch(m_Version) {
    case SP2: assert (false && "Not implemented");
    case SP3: return (0x004ab3c8 - 0x400000 + 0x804d7000);
   }
   assert(false && "Unknown OS version\n");
   return 0;
}

uint64_t WindowsMonitor::GetDllUnloadPc() const
{
   switch(m_Version) {
    case SP2: assert (false && "Not implemented");
    case SP3: return 0x7c91e12a; //0x7c91dfb3; //LdrUnloadDll
   }
   assert(false && "Unknown OS version\n");
   return 0;
}
