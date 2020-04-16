# Symbion: Interleaving Symbolic with Concrete Execution
<a href=""> <img align="right" width="250"  src="symbion_paper.png"> </a>

This repository contains the malware analysis use cases presented in our CNS paper <a href="127.0.0.1">"Symbion: Interleaving Symbolic with Concrete Execution"</a> (<a href="">slides</a>). Our technique allows interleaving symbolic execution with a concrete execution, focusing the symbolic exploration only on interesting portions of code. 

The implementaion of Symbion is publicly available on <a href="https://github.com/angr/angr">angr</a>'s master.
For a complete example on how to leverage this technique for your analyses refer to our <a href="https://angr.io/blog/angr_symbion/">blog post</a>.

We provide support (ping @degrigis) on how to use Symbion through our Slack channel, you can ask for an invite <a href="https://angr.io/invite/.">here</a>.


Happy hacking!

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
