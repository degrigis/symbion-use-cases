'''
GOAL
====
Understading which command triggers a specific functionality of the malware.

PROBLEMS: 
=========
The malware forks at the beginning and angr has problems in starting from the middle of the binary
since we miss some context.

REFERENCE WRITE-UP: 
===================
1) https://blog.trendmicro.com/trendlabs-security-intelligence/bashlite-iot-malware-updated-with-mining-and-backdoor-commands-targets-wemo-devices/

NOTES:
======
1) This script assumes that you are running the malware on an Ubuntu Vm that you can reach via ssh.
You can specify this information using this script:

python bashlite_analyze.py <VM_IP> <GDB_SERVER_PORT> <SSH_USER> <SSH_PASSWORD>

The binary has to be inside the virtual machine to be run concretely
and on the local machine to create an angr project. 
The name of the binary it's specified in the global var MALWARE_BIN in this python script.

MALWARE URL:
============
- https://www.virustotal.com/gui/file/81cbb253ef6ad4803e3918883eed3ec6306ef12e7933c5723bd720d55d13a46a/detection
- MD5: 3d257d80963c9c905e883b568f997550
'''

import angr
import claripy
import avatar2
import logging
import warnings
import networkx
import paramiko
import sys

from angr.procedures.libc.strstr import strstr
from angr.procedures.libc.atoi import atoi
from angr.procedures.libc.strchr import strchr
from angr_targets import AvatarGDBConcreteTarget

l = logging.getLogger(name=__name__)
l.setLevel(logging.DEBUG)
warnings.filterwarnings(action='ignore',module='.*paramiko.*')

###########################################################################################
# HELPERS
###########################################################################################
def connectToVM():
    global SSH_CLIENT
    SSH_CLIENT = paramiko.SSHClient()
    SSH_CLIENT.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    SSH_CLIENT.connect(VM_IP, port=22, username=SSH_USER, password=SSH_PASSWORD)

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
# GLOBAL OBJECTS
###########################################################################################
SSH_CLIENT = None
AVATAR_GDB = None
ANGR_PROJECT = None

# GLOBAL VARS USED LATER
symbolic_buffer_size = 16
command_buffer_address = None
command_buffer_symbolic = None
command_buffer_data = None

###########################################################################################

###########################################################################################
# CONFIG
###########################################################################################
MALWARE_BIN = '81cbb253.bin'
VM_IP = ''
GDB_SERVER_PORT = None
SSH_USER = ''
SSH_PASSWORD = ''

# NOTE: Remember to change the flag of the binary 'DLL can move' so we can use absolute
# addresses to set breakpoints.
RESTART_MALWARE = "gdbserver 0.0.0.0:9999 /home/sample/Desktop/" + MALWARE_BIN

###########################################################################################

###########################################################################################
# INTERESTING ADDRESSES
###########################################################################################
AFTER_ECHOCONNECTION = 0x40A5CE
BEFORE_RECVLINE = 0x40ABD3
AFTER_RECVLINE = 0x40ABDD
RECVLINE_START = 0x40154D
TRIM = 0x40A755
STRSTR = 0x40C964
REPNESCASB = 0x40036F
CFG_BYPASS = 0x406991
ECHOCOMMAND = 0x407EC4
OVH_FLOOD = 0x409D92
ATOI = 0x40E6E0
LISTFORK = 0x401AE5
STRCHR = 0x40C520
CUSTOM_END_CFG_REGION = 0x40E6F1
###########################################################################################


###########################################################################################
# CUSTOM HOOKS
###########################################################################################
# Let's simplify the recvline by just putting a symbolic buffer in the command buffer.
# The malware is also dead so we are reviving it! ( MALWARE NECROMANCY! )
def hook_recvLine(state):
    global command_buffer_address
    global command_buffer_symbolic

    command_buffer_address = state.regs.rsi
    command_max_size = state.regs.edx # this is 0x10000
    command_buffer_symbolic = claripy.BVS('CommandBuffer', 8*symbolic_buffer_size)
    state.memory.store(command_buffer_address, command_buffer_symbolic)
    state.regs.rax = symbolic_buffer_size # everything is fine, this contains the size of the parsed command.
    state.regs.rip = 0x40abdd # skip, go to next instruction!


# This was responsible to calculate the length of strings inside
# the trimming, but as for now we are skipping trimming.
def hook_repnescasb(state):
    state.regs.rcx = symbolic_buffer_size
    state.regs.rip = 0x400371

def hook_repecmpsb(state):

    # We have to generate here 2 states, one in which the comparison is True
    # and one in which the comparison is False.

    # These checks are in always in this form inside the binary:

    '''
    .text:0000000000407F1E F3 A6       repe cmpsb
    .text:0000000000407F20 0F 97 C2    setnbe  dl
    .text:0000000000407F23 0F 92 C0    setb    al
    .text:0000000000407F26 89 D1       mov     ecx, edx
    .text:0000000000407F28 28 C1       sub     cl, al
    .text:0000000000407F2A 89 C8       mov     eax, ecx
    .text:0000000000407F2C 0F BE C0    movsx   eax, al
    .text:0000000000407F2F 85 C0       test    eax, eax
    '''

    # So the next address is the one where we have test eax, eax.

    str1 = state.memory.load(state.regs.rdi, state.regs.rcx)
    str2 = state.memory.load(state.regs.rsi, state.regs.rcx)

    myblock = state.block(state.addr + 2)

    ins_addr = None
    for ins in myblock.capstone.insns:
        if ins.mnemonic == 'test' and ins.op_str == 'eax, eax':
            ins_addr = ins.address
            break

    state.regs.rax = claripy.If(str1 == str2, claripy.BVV(0,64),claripy.BVV(1,64))
    state.regs.rip = ins_addr


# Trimming matters only if we have spaces in the command received.
# As for now we can safely skip it tho.
def hook_trim(state):
    state.regs.rip = 0x40A75A

# The malware always delegates childre to do stuff, we can safely
# hook the forking procedure and act as if we are the children.
class MyFork(angr.SimProcedure):
    #pylint:disable=arguments-differ
    def run(self, ptr):
        return 0 # always return like we are a child

###########################################################################################

# LET'S START!

if __name__== "__main__":

    try:
        VM_IP = sys.argv[1]
        GDB_SERVER_PORT = sys.argv[2]
        SSH_USER = sys.argv[3]
        SSH_PASSWORD = sys.argv[4]
    except Exception:
        print("Usage: python bashlite_analyze.py <VM_IP> <GDB_SERVER_PORT> <SSH_USER> <SSH_PASSWORD>")
        sys.exit(1)

    # Connect via SSH to the concrete environment.
    connectToVM()

    # Star the malware under gdbserver.
    sendCommandToVM(RESTART_MALWARE)

    # Let's instantiate the target and the angr project.
    AVATAR_GDB   = AvatarGDBConcreteTarget(avatar2.archs.x86.X86_64, VM_IP, GDB_SERVER_PORT)
    ANGR_PROJECT = angr.Project("./"+MALWARE_BIN, concrete_target=AVATAR_GDB, use_sim_procedures=True,
                     page_size=0x1000)

    entry_state = ANGR_PROJECT.factory.entry_state(add_options=angr.options.unicorn)

    # Enable following childs ( the malware spawns a children and we must follow it to reach the dispatcher )
    entry_state.project.concrete_target.target.protocols.execution.console_command("set follow-fork-mode child", "done")

    # Let's sync right after the echoconnection.
    new_concrete_state = execute_concretly(ANGR_PROJECT, entry_state, AFTER_ECHOCONNECTION, [], [])

    # Resume the malware by changing rax to switch to the correct branch.
    new_concrete_state = execute_concretly(ANGR_PROJECT, new_concrete_state, BEFORE_RECVLINE, [], [("rax", claripy.BVV(0,8*4) )])

    ##################################################################################
    # 'Everyday I'm hoooking it' - Optimize the symbolic exec and insert custom hooks.
    ##################################################################################

    # Hooking of instructions and other stuff.
    ANGR_PROJECT.hook(RECVLINE_START, hook_recvLine)
    ANGR_PROJECT.hook(REPNESCASB, hook_repnescasb)
    ANGR_PROJECT.hook(TRIM, hook_trim)

    # Let's hook right now all the libc functions identified.
    ANGR_PROJECT.hook(STRSTR, strstr())
    ANGR_PROJECT.hook(ATOI, atoi())
    ANGR_PROJECT.hook(STRCHR, strchr())

    # Hooking the listFork function with a new SimProc that just return 0 ( "I am the child!" )
    ANGR_PROJECT.hook(LISTFORK, MyFork())

    ###########################################################

    # Ok let's try to reach the commands dispatcher symbolically.
    simgr = ANGR_PROJECT.factory.simgr(new_concrete_state)
    simgr.use_technique(angr.exploration_techniques.DFS())

    print("Symbolically executing to reach the dispatcher echocommand")
    next_simgr = simgr.explore(find=ECHOCOMMAND)

    print("Reached the command dispatcher echocommand")
    next_state = next_simgr.found[0]


    # Ok, right now we have the input to reach the dispatcher, but due to previous
    # approximation ( strstr ) we have a very simple input ( ! \r\n ).
    # Instead of waiting for the correct input to show up we can do 2 things:
    #    1- Either synchronize the concrete process up to this point and reset the symbuffer.
    #    2- Just reset the symbolic buffer where the command dispatcher expects the command to be.
    #
    # We are going for the second one here.

    print("Restoring symbolic buffer")
    command_buffer_address2 = next_state.regs.rax
    command_buffer_symbolic2 = claripy.BVS('CommandBuffer2', 8 * symbolic_buffer_size)
    # This is another buffer that the malware uses to decide what to do, let's make it symbolic.
    command_tokens_symbolic_size = claripy.BVS('CommandTokens', 8 * 8)

    print("Setting symbolic buffer at {} on state {}".format(str(command_buffer_address2),str(next_state)))
    print("Setting symbolic register edi on state {}".format(str(next_state)))
    next_state.memory.store(command_buffer_address2, command_buffer_symbolic2)
    next_state.regs.edi = command_tokens_symbolic_size

    # Now we want to reach a specific functionality in the program, for example the ovhflood.
    # To do that we want to see which BB we have to execute to reach that call, let's compute this
    # information statically using the CFG!
    print("Creating malware CFG")
    whole_cfg = ANGR_PROJECT.analyses.CFGFast(regions=[(ECHOCOMMAND, CUSTOM_END_CFG_REGION)],
                             force_complete_scan=False, normalize=False)

    # Now let's extract the function object for the dispatcher.
    func_echocommand = whole_cfg.functions.get_by_addr(ECHOCOMMAND)

    print("Looking for reachibility for OVH_FLOOD")

    # Let's dump the bb we need to traverse to reach the ovhflood
    node_start = func_echocommand.get_node(addr=ECHOCOMMAND)
    node_end   = func_echocommand.get_node(addr=OVH_FLOOD)
    shortest_path = networkx.shortest_path(func_echocommand.graph, source=node_start, target=node_end)
    #networkx.drawing.nx_pydot.write_dot(echocommand_cfg.graph, "cfg.dot") # xdot to view this


    # Now we have to post-process the shortest-path and put all the instructions contained in the basic blocks
    # that are inside that list.
    # This should get rid of the problem that there are some instructions that split the cfg ( repe cmpsb ) that
    # are not showing up in the shortest path, but that are actually executed symbolically.
    trace = []

    for bb in shortest_path:
        bblock = next_state.block(addr=bb.addr)
        trace.extend(bblock.instruction_addrs)

    # repe cmpsb is a pretty bad instruction for angr.
    # Since the buffer is symbolic we don't want to generate a state for every character that is
    # different from the hardcoded string. We are going to generate just two states, one in which the
    # string is not the one that the malware is checking against and the other one constrained to that string.
    print("Hooking repe cmpsb with a custom strcmp")

    # First, we need to grab all the repe cmpsb and hook a strcmp there.
    for node in whole_cfg.graph.nodes:
        if node and node.instruction_addrs:
            for ins_addr in node.instruction_addrs:
                for ins in next_state.block(addr=ins_addr, num_inst=1).capstone.insns:
                    if ins.mnemonic == 'repe cmpsb':
                        ANGR_PROJECT.hook(ins.address, hook_repecmpsb)

    print("Starting Directed Symbolic Execution to reach OVH_FLOOD")

    # Let's create a new simulation manager!
    simgr = ANGR_PROJECT.factory.simgr(next_state)

    # This is the list of call that we are going to meet in the dispatcher, we have SimProcedures there
    # But these addresses are not showing up in the shortest path so we add them manually in this
    # array.
    EXTERNAL_CALLS = [ ATOI , LISTFORK, STRCHR ]

    # Let's step!
    while True:

        simgr = simgr.step()

        #print("Active states before")
        #print(simgr.stashes["active"])

        keep_active = []
        for state in simgr.active:
            address = state.solver.eval(state.regs.rip)

            # Get rid of the states that are now in the path we are following!
            if address in trace or address in EXTERNAL_CALLS:
                keep_active.append(state)

            simgr.stashes["active"] = keep_active # Updating the simgr.active states!

        if simgr.stashes["active"]:
            #next_state = next_simgr.active[0]
            #print("Active states after")
            #print(simgr.stashes["active"])

            next_state = simgr.one_active

            # End?
            if next_state.solver.eval(next_state.regs.rip) == OVH_FLOOD:
                print("Reached OVHFLOOD")
                concrete_input = next_state.solver.eval(command_buffer_symbolic2, cast_to=bytes)
                print("Command to issue: {} ".format(concrete_input))

                concrete_input2 = next_state.solver.eval(command_tokens_symbolic_size)
                print("Token numbers: {} ".format(hex(concrete_input2)))

                break

        else:
            print("simgr is empty, something went wrong during the Directed Symbolic Execution. Terminating.")
            break

    # Just in case.
    import ipdb; ipdb.set_trace()

    teardown()
    SSH_CLIENT.close()
