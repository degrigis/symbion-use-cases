'''
GOAL
====
Understanding which return value we need to bypass an evasion technique.

PROBLEM: 
=========
We have to investigate manually which value we need to reach the correct malware behavior,
here we can apply surgically a symexecution and simply get that value.

REFERENCE WRITE-UPs: 
===================
1) https://www.lastline.com/labsblog/malware-evasion-techniques/

NOTES:
======
1) This script assumes that you are running the malware on a Windows7 Vm that you can reach via ssh.
You can specify this information using this script:

python analyze.py <VM_IP> <GDB_SERVER_PORT> <SSH_USER> <SSH_PASSWORD>

The binary has to be inside the virtual machine to be run concretely
and on the local machine to create an angr project. 
The name of the binary it's specified in the global var MALWARE_BIN in this python script.

2) Make sure you have disabled the 'DLL can move' feature of the binary so we can use absolute addresses
   for breakpoints. Use CFFExplorer to edit the binary or similar software.
   See this -> https://www.sans.org/blog/tools-for-analyzing-static-properties-of-suspicious-files-on-windows/.

MALWARE URL:
============
- https://www.virustotal.com/gui/file/47d02763457fe39edd3b84f59e145330ffd455547da7cbf67c3f0cb3ddf10542/detection   
- MD5: 53f6f9a0d0867c10841b815a1eea1468
'''



import angr
import avatar2
import paramiko
import logging
import warnings
import sys

l = logging.getLogger(name=__name__)
l.setLevel(logging.DEBUG)

warnings.filterwarnings(action='ignore',module='.*paramiko.*')

from angr_targets import AvatarGDBConcreteTarget
from angr.procedures.win32.GetProcessAffinityMask import GetProcessAffinityMask
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
MALWARE_BIN = '53f6f9a0d.exe'
VM_IP = ''
GDB_SERVER_PORT = None
SSH_USER = ''
SSH_PASSWORD = ''

# Remember to change the flag of the binary 'DLL can move' so we can use absolute
# addresses to set breakpoints.
RESTART_MALWARE = "C:\MinGW\\bin\\gdbserver.exe 0.0.0.0:9999 E:\\" + MALWARE_BIN

###########################################################################################

###########################################################################################
# INTERESTING ADDRESSES
###########################################################################################
END_UNPACKING = 0x439D2E
MALWARE_MAIN =  0x40FAE6

# TODO address taken from the debugging, we can extract it automatically.
CALL_TO_GetProcessAffinityMask = 0x7502A889
RANSOMWARE_BEHAVIOR = 0x4214e4
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

# LET'S START!

if __name__== "__main__":

    try:
        VM_IP = sys.argv[1]
        GDB_SERVER_PORT = sys.argv[2]
        SSH_USER = sys.argv[3]
        SSH_PASSWORD = sys.argv[4]
    except Exception:
        print("Usage: python analyze.py <VM_IP> <GDB_SERVER_PORT> <SSH_USER> <SSH_PASSWORD>")
        sys.exit(1)

    connectToVM()
    sendCommandToVM(RESTART_MALWARE)

    AVATAR_GDB = AvatarGDBConcreteTarget(avatar2.archs.x86.X86, VM_IP, GDB_SERVER_PORT)
    ANGR_PROJECT = angr.Project("./"+MALWARE_BIN, concrete_target=AVATAR_GDB, use_sim_procedures=True,
                     page_size=0x1000)

    entry_state = ANGR_PROJECT.factory.entry_state(add_options=angr.options.unicorn)
    new_concrete_state = execute_concretly(ANGR_PROJECT, entry_state, END_UNPACKING, [], [])
    new_concrete_state = execute_concretly(ANGR_PROJECT, new_concrete_state, CALL_TO_GetProcessAffinityMask, [], [])

    new_concrete_state.project.hook(CALL_TO_GetProcessAffinityMask, GetProcessAffinityMask())
    new_concrete_state.options.update(o.refs)

    simgr = ANGR_PROJECT.factory.simgr(new_concrete_state)
    simgr.use_technique(angr.exploration_techniques.DFS())

    while True:
        next_simgr = simgr.step()
        next_state = next_simgr.active[0]
        print(next_state)
        address = next_state.solver.eval(next_state.regs.pc)

        if address == RANSOMWARE_BEHAVIOR:
            l.warn("Reached ransomware behavior, concretize memory returned by GetProcessAffinityMask!")
            break

    # DO A 
    # next_state.mem[<address of lpSystemAffinityMask of GetProcessAffinityMask(2nd arg)> ].int.concrete
    
    import ipdb; ipdb.set_trace()
    teardown()
    SSH_CLIENT.close()


