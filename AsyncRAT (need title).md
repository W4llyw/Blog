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
Ok this is where we really get into things [dnSpy](https://github.com/dnSpy/dnSpy) is a debugger, decompiler, and a .NET/Unity assembly editor. Perfect for diving into this malware.

Initially looking at dnSpy it is pretty overwhelming and took some research on where I should look first.

![dnSpy](https://github.com/W4llyw/Blog/blob/main/Images/AsyncRAT/dnSpy.png)

Well it was pretty straightforward actually seems like the best place to start was called the Entry Point. See the Entry Point is the very first instruction that executes in a process. This is where the Operating System gives control to the application so it can start performing these instructions that the Entry Point points to.

![Entry Point](https://github.com/W4llyw/Blog/blob/main/Images/AsyncRAT/Entry%20Point.png)

This led to the `Client` namespace, which contained the `Settings` class and I noticed something that was in the original blog post I referenced earlier.

![Client to Settings](https://github.com/W4llyw/Blog/blob/main/Images/AsyncRAT/Client%20to%20Settings.png)

Within the `Settings` class there is a method called `InitializeSettings()`, this basically contains the hardcoded config for the malware which is encrypted before execution to avoid detection via static analysis.

![InitializeSettings](https://github.com/W4llyw/Blog/blob/main/Images/AsyncRAT/InitializeSettings.png)

![Encrypted Variables](https://github.com/W4llyw/Blog/blob/main/Images/AsyncRAT/Encrypted%20Variables.png)

The use of the `InitializeSettings` method is a somewhat ingenious technique, it serves two purposes the first is that it doesn't require the process to rely on an external .config file which makes its footprint smaller and the second is to decrypt these hardcoded configs the malware would have to be ran.

Looking further down the assembly explorer I notice some very interesting namespaces: `Clients.Modules.Passwords.Targets`, `Clients.Modules.Passwords.Targets.Browsers`, `Clients.Modules.Passwords.Targets.Messengers`, and `Clients.Modules.Passwords.Targets.System`.
Looking through these it seems like this RAT has been modified into an info stealer, targeting a multitude of information such as Browser information such as stored passwords, and credit card information, Crypto wallets, Discord or Telegram tokens, keylogging,and WebCam screenshots.

Browser Information Stealing:
![Stealing Browser Info](https://github.com/W4llyw/Blog/blob/main/Images/AsyncRAT/Targeting%20browser%20info.png)

Stealing Crypto Wallets:
![Crypto](https://github.com/W4llyw/Blog/blob/main/Images/AsyncRAT/Targeting%20Crypto%20wallets.png)

Discord and Telegram token theft:
![Discord Token](https://github.com/W4llyw/Blog/blob/main/Images/AsyncRAT/Targeting%20Discord%20token.png)

Sending Keylogger logs to Telegram:
![Exfil of Keylogger](https://github.com/W4llyw/Blog/blob/main/Images/AsyncRAT/Sending%20Keylogging%20to%20Telegram.png)

Ok so now I am 100% sure this is an info stealer and I noticed in the `InitializeSettings` method there were two fields that referenced Telegram: `TelegramChatID` and `TelegramToken`. But they are encrypted which means I would need to run the malware to see the decrypted data.

In comes dnSpy once again to save the day, I can "partially" run the malware in dnSpy by setting a breakpoint and view what the process has done up unto that point in memory.I set the breakpoint to the return at the very bottom of the `InitializeSettings` method, then run the debugger.

Setting the Breakpoint:
![Breakpoint](https://github.com/W4llyw/Blog/blob/main/Images/AsyncRAT/Breakpoint%20set.png)

Once the debugger has ran the process up until my breakpoint I check the static field in memory.
And there they all are, all the variables in cleartext!

Decrypted malware config variables:
![Fields Decrypted](https://github.com/W4llyw/Blog/blob/main/Images/AsyncRAT/all%20variables%20decrypted.png)

There is some very juicy info here but we will and will keep moving and looking more into the malware sample. 
One thing I did notice in the decrypted settings is that the `Anti` field is `false` (which would have made this analysis a lot more difficult). This was the anti analysis method that is seen in other AsyncRAT samples and even though this is a modified version of AsyncRAT it still contained the `AntiAnalysis` method, which I took an interest in and thought it should at least be brought up here. It checks for a multitude of things like static analysis tools, weather it is sand boxed or not, and if it's being ran in hypervisor such as VirtualBox or VMware.

![AntiAnalysis](https://github.com/W4llyw/Blog/blob/main/Images/AsyncRAT/AntiAnalysis.png)

If any of these return true the process precedes to a method called `FakeErrorMessage()` which pops up a message box with a fake error message then executes `SelfDestruct.Melt()`. This method deletes the .bat file, kills the malware's process, deletes the malware's current working path, and deletes the DotNetZip.dll. 

Self Destruction:
![Melt](https://github.com/W4llyw/Blog/blob/main/Images/AsyncRAT/Melt.png)