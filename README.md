# Symbion: Interleaving Symbolic with Concrete Execution
<a href="https://seclab.cs.ucsb.edu/files/publications/gritti2020_symbion.pdf"> <img align="right" width="250"  src="symbion_paper.png"> </a>

This repository contains the malware analysis use cases presented in our CNS paper <a href="127.0.0.1">"Symbion: Interleaving Symbolic with Concrete Execution"</a> (<a href="symbion_slides.pdf">slides</a>). Our technique allows interleaving symbolic execution with a concrete execution, focusing the symbolic exploration only on interesting portions of code. 

The implementaion of Symbion is publicly available on <a href="https://github.com/angr/angr">angr</a>'s master.
For a complete example on how to leverage this technique for your analyses refer to our <a href="https://angr.io/blog/angr_symbion/">blog post</a>.

We provide support (ping @degrigis) on how to use Symbion through our Slack channel, you can ask for an invite <a href="https://angr.io/invite/.">here</a>.


Happy hacking!

## :warning: WARNING :warning:
angr and Symbion drastically changed since the publication of this work. Therefore, the use-cases presented in this repo must be re-written. 
Refer to the test case [here](https://github.com/angr/angr-targets/blob/master/tests/test_concrete_not_packed_elf64.py) for the latest working version and to the state of the work [here](https://github.com/angr/angr/issues/2701).

## BibTex:
```
@inproceedings{gritti2020symbion,
 author = {Gritti, Fabio and Fontana, Lorenzo and Gustafson, Eric and Pagani, Fabio and Continella, Andrea and Kruegel, Christopher and Vigna, Giovanni},
 booktitle = {Proceedings of the IEEE Conference on Communications and Network Security (CNS)},
 month = {June},
 title = {SYMBION: Interleaving Symbolic with Concrete Execution},
 year = {2020}
}
```
