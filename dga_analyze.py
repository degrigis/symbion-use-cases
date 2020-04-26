'''
GOAL
====
Reaching the gethostbyname and understand if it depends from the identified GetSystemTime.

PROBLEMS: 
=========
Understanding that dependency manually could be very time consuming.

REFERENCE WRITE-UPs: 
===================
1) https://blog.avast.com/2013/06/18/your-facebook-connection-is-now-secured/
2) https://www.hybrid-analysis.com/sample/ec8b88a96d1b4917334bdad7f2e580ead4d9b71d111a1591bb5b965da3e27cf6/5cd47cb5038838b35b7b23cd

NOTES:
======
1) This script assumes that you are running the malware on an Windows7 Vm that you can reach via ssh.
You can specify this information using this script:

python dga_analyze.py <VM_IP> <GDB_SERVER_PORT> <SSH_USER> <SSH_PASSWORD>

The binary has to be inside the virtual machine to be run concretely
and on the local machine to create an angr project. 
The name of the binary it's specified in the global var MALWARE_BIN in this python script.

2) Make sure you have disabled the 'DLL can move' feature of the binary so we can use absolute addresses
   for breakpoints. Use CFFExplorer to edit the binary or similar software.
   See this -> https://www.sans.org/blog/tools-for-analyzing-static-properties-of-suspicious-files-on-windows/.

MALWARE URL:
============
- https://www.virustotal.com/gui/file/ec8b88a96d1b4917334bdad7f2e580ead4d9b71d111a1591bb5b965da3e27cf6/detection
- MD5: 221c235bc70586ce4f4def9a147b8735
'''


import angr
import avatar2
import claripy
import paramiko
import time
import warnings
import sys
warnings.filterwarnings(action='ignore',module='.*paramiko.*')

from angr_targets import AvatarGDBConcreteTarget
from angr.procedures.win32.gethostbyname import gethostbyname
from angr import options as o

###########################################################################################
# GLOBAL OBJECTS
###########################################################################################
SSH_CLIENT = None
AVATAR_GDB = None
ANGR_PROJECT = None
###########################################################################################

###########################################################################################
# CONFIG
###########################################################################################
MALWARE_BIN = 'ec8b88.exe'
VM_IP = ''
GDB_SERVER_PORT = None
SSH_USER = ''
SSH_PASSWORD = ''
RESTART_MALWARE = "C:\MinGW\\bin\\gdbserver.exe 0.0.0.0:9999 E:\\" + MALWARE_BIN
###########################################################################################

###########################################################################################
# INTERESTING ADDRESSES
###########################################################################################
CALL_TO_MAIN_MALWARE_FUNCITON = 0x408BBF
EXPECTED_ADDRESS = 0x404ac0
REAL_ADDRESS_PTR = 0x4263ac
CFG_REGION_END = 0x0040C4D8
GET_SYSTEM_TIME_BB = 0x40c488
DECIDE_MALWARE_NAME = 0x405340
###########################################################################################

###########################################################################################
# HELPERS
###########################################################################################
def connectToVM():
    global SSH_CLIENT
    SSH_CLIENT = paramiko.SSHClient()
    SSH_CLIENT.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    SSH_CLIENT.connect(VM_IP, port=22, username=SSH_USER, password=SSH_PASSWORD)


def setup_x86():
    print("Configure a windows machine with a static IP  %s. "
          "Check windows firewall configurations to be sure that the connections to %s:%s are not blocked\n"
          "Install gdbserver on the machine, b"
          "e careful the architecture (x86 or x64) of gdbserver should be the same as the debugged binary.\n"
          "Currently using Cygwin for 32 bit gdbserver and Cygwin for 64 bit gdbserver" % (VM_IP,
                                                                                           VM_IP,
                                                                                           GDB_SERVER_PORT))

    print("On windows machine execute gdbserver %s:%s path/to/binary.exe" % (VM_IP, GDB_SERVER_PORT))
    input("Press enter when gdbserver has been executed")

def sendCommandToVM(cmd):
    (stdin, stdout, stderr) = SSH_CLIENT.exec_command(cmd)

def teardown():
    global AVATAR_GDB
    if AVATAR_GDB:
        AVATAR_GDB.exit()

def execute_concretly(p, state, address, memory_concretize=[], register_concretize=[], timeout=0):
    simgr = p.factory.simgr(state)
    simgr.use_technique(angr.exploration_techniques.Symbion(find=[address], memory_concretize=memory_concretize,
                                                            register_concretize=register_concretize, timeout=timeout))
    exploration = simgr.run()
    return exploration.stashes['found'][0]

###########################################################################################


###########################################################################################
# CUSTOM HOOKS
###########################################################################################

# defining my gethostbyname to check symbolic name!
def mygethostbyname(fn):
    def _mygethostbyname(*args, **kwargs):
        simproc_obj = args[0]
        current_state = simproc_obj.state
        domain_address = args[1]
        solver = current_state.solver
        
        # domain is symbolic and depends on GetFileSystemTime at 0x40c488
        #print(current_state.memory._read_from(current_state.solver.eval(domain_address),8))

        # ANALYZE SYMBOLIC DOMAIN HERE! :)
        import ipdb; ipdb.set_trace()

        fn(*args, **kwargs) # execute normal SimProc

    return _mygethostbyname

###########################################################################################

# LET'S START!
if __name__== "__main__":

    try:
        VM_IP = sys.argv[1]
        GDB_SERVER_PORT = sys.argv[2]
        SSH_USER = sys.argv[3]
        SSH_PASSWORD = sys.argv[4]
    except Exception:
        print("Usage: python dga_analyze.py <VM_IP> <GDB_SERVER_PORT> <SSH_USER> <SSH_PASSWORD>")
        sys.exit(1)

    connectToVM()
    sendCommandToVM(RESTART_MALWARE)

    # This is used in order to restart the malware if the
    # internal synchronization has not happened correctly.
    def analysis_step_1():

        global ANGR_PROJECT
        global AVATAR_GDB

        AVATAR_GDB = AvatarGDBConcreteTarget(avatar2.archs.x86.X86, VM_IP, GDB_SERVER_PORT)
        ANGR_PROJECT = angr.Project("./"+MALWARE_BIN, concrete_target=AVATAR_GDB, use_sim_procedures=True,
                         page_size=0x1000)

        entry_state = ANGR_PROJECT.factory.entry_state()

        # we have to patch the number of seconds the thread are waiting for being wake up!
        PATCH_1 = (claripy.BVV(0x004049bc,8*4), claripy.BVV(0x68ffffffff,8*5))

        new_concrete_state = execute_concretly(ANGR_PROJECT, entry_state, CALL_TO_MAIN_MALWARE_FUNCITON, [PATCH_1], [])

        # Check if we have the correct address at memory, if not restart the program and do it again!
        # ( issue command via ssh )

        if new_concrete_state.mem[REAL_ADDRESS_PTR].dword.concrete != EXPECTED_ADDRESS:
            teardown()
            sendCommandToVM(RESTART_MALWARE)
            time.sleep(2)
            print("Malware doesn't synchronized correctly as expected, restarting it now.")
            return None
        else:
            print("Malware synchronization happen as expected, proceeding.")
            return new_concrete_state


    new_concrete_state = None
    while new_concrete_state == None:
        new_concrete_state = analysis_step_1()

    # We are good!
    new_concrete_state = execute_concretly(ANGR_PROJECT, new_concrete_state, EXPECTED_ADDRESS, [], [])
    new_concrete_state = execute_concretly(ANGR_PROJECT, new_concrete_state, 0x405337, [], [])
    assert(new_concrete_state.solver.eval(new_concrete_state.regs.pc) == 0x405337)

    # Now we need to set the memory pointed by ecx to the string "usfqvololjv.exe"
    PATCH_2 = (new_concrete_state.regs.ecx, claripy.BVV(0x75736671766f6c6F6C6A762E65786500,8*16))
    new_concrete_state = execute_concretly(ANGR_PROJECT, new_concrete_state, GET_SYSTEM_TIME_BB, [PATCH_2], [])
    assert(new_concrete_state.solver.eval(new_concrete_state.regs.pc) == GET_SYSTEM_TIME_BB)

    simgr = ANGR_PROJECT.factory.simgr(new_concrete_state)
    new_state = simgr.step()  # should be the call to GetSystemFileTime
    new_state = simgr.step()  # immediately after that
    new_state = new_state.active[0]
    new_state.options.update(o.refs)

    gethostbyname.run = mygethostbyname(gethostbyname.run)

    simgr = ANGR_PROJECT.factory.simgr(new_state)
    simgr.use_technique(angr.exploration_techniques.DFS())
    simgr.run()  # waiting for ipdb when gethostbyname is executed! :-)

    teardown()

    SSH_CLIENT.close()
