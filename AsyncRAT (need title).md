# AsyncRAT Dive (Need Title)


I recently looked into AsyncRAT in another blog post, that one is what I would call a "lite" version of malware analysis. Honestly it should have been called a fire starter as it lit a fire under me to really get into the internals of malware and do a deeper dive myself. 
My goal this time around was to get into the code of a sample of AsyncRAT that I find online, understand what it does and why. All at the same time learning how to interact with malicious files like this safely and with what tools. Learning those tools and hopefully gaining a better understanding of a language I am unfamiliar with.

So without further delay let me introduce you to just that my attempt at a deeper analysis of the AsyncRAT which turns out to have a bit of a twist and a small victory in the end!

### The setup
If I am going to download and dismantle software that is built to ruin peoples day I need a safe to place to do it all in and since this is my first time doing this the tool to do it. Conveniently enough I had a Linux machine I could run a windows (I chose windows because it's the most targeted OS) vm on, I figured this was the safest bet having the guest and the host running two different operating systems in case of any kind of breakout.
Now I had to find the tools that analyst use to do their analysis and I have heard of a few pre-built OSs that would be a great place to get started namely [REMnux](https://remnux.org/#home) and [FlareVM](https://github.com/mandiant/flare-vm). REMnux is linux based so FlareVM it was.

*FlareVM is technically not a OS in the since that REMnux is a linux distro. FlareVM is a collection of software installation scripts for Windows*

Setting up FlareVm was really simple and Mandiant provides really clear instructions on their GitHub page which seems to be pretty well maintained. 

### Finding the RAT
Surprisingly finding malware on the internet is fairly easy, it's as simple as going to the store or in this case the bazaar.
The [Malware Bazaar](https://bazaar.abuse.ch) is just that place. I searched for the AsyncRAT signature and found a lot and they were even posted that same day! I settled on the one pictured below, downloaded it, and.......Immediately disconnected my VM from the internet.

**Take Caution When Downloading From Any Site That Hosts Malware These Are Live Samples**

![Malware Bazaar](https://github.com/W4llyw/Blog/blob/main/Images/AsyncRAT/Malware%20Bazaar.png) 


### The Analysis

#### Strings
Before diving into the code with a decompiler I figured I would look at it from a very high point of view via [Strings](https://learn.microsoft.com/en-us/sysinternals/downloads/strings). 

During my search through the malware's strings some very interesting things jumped out to me, most notably the strings TelegramToken and TelegramChatID. I knew that the sample of AsyncRAT I found would be different than the one found in the [this](https://blog.qualys.com/vulnerabilities-threat-research/2022/08/16/asyncrat-c2-framework-overview-technical-analysis-and-detection) post (which was what made me want to look further into AsyncRAT) but the mention of a telegram ID was a big surprise!

![Strings Findings](https://github.com/W4llyw/Blog/blob/main/Images/AsyncRAT/Strings.png)


#### PEStudio
I needed to know what this thing was built with so I can dissect it using the proper tool. 
In comes [PEStudio](https://www.winitor.com) it can identify a multitude of things for initial static malware analysis, but I just needed it to identify what my sample was made with.
Ok a 32bit executable built written in C#

![PEStudio](https://github.com/W4llyw/Blog/blob/main/Images/AsyncRAT/Pestudio%20info.png)


#### dnSpy
