# Title


I was looking for my next journey into malware analysis and this time around I decided to take a look at QuasarRat. It's a .net based RAT that is a bit more complicated than AsyncRAT and seemed to have been favored by Advanced Persistent Threats (APT) based out of china for awhile. According to an article posted by [Huntress](https://www.huntress.com/threat-library/threat-actors/apt10) parts of the APT (APT10) group were indicted in 2018. This made me interested in why or who is still using it today and possibly exposing their infrastructure, lets see what we can find out.

### Finding the sample
As usual getting malware from the internet is never difficult. By using MalwareBazaar's search syntax `signature:QuasarRAT` I pulled up all the posted malware with the QuasarRAT signature. Since it was sorted by latest posted I chose the first one that showed up and just went for it.

**Take Caution When Downloading From Any Site That Hosts Malware as These Are Live Samples**

![MalwareBazaar](https://github.com/W4llyw/Blog/blob/main/Images/QuasarRAT/Bazaar.png)

### An Initial look
Detect It Easy (DIE) confirms that it is a .net application, and mentions that it's packed in the initial scan.

![DIE](https://github.com/W4llyw/Blog/blob/main/Images/QuasarRAT/DIE.png)

DIE will also show you just how packed the malware is by displaying its entropy (randomness).

![Entropy](https://github.com/W4llyw/Blog/blob/main/Images/QuasarRAT/DIE%20Entropy.png)

93%! Well I said I wanted something more obfuscated and complex.
Lets take a look at PEStudio to see if some of the imports can tell me anything.

![PeStudio](https://github.com/W4llyw/Blog/blob/main/Images/QuasarRAT/Low%20Imports.png)

...5. There are 5 imports. And they didn't seem to stand out much, I mean `GetCurrentThread` could possibly be something but on its own not likely. I looked up the MiniDump api and it could be used for credential theft or information gathering, but the low amount of imports definitely means heavy obfuscation.

### Diving in
Ok time to get into this thing and see just how obfuscated this thing is.

![Chinese](https://github.com/W4llyw/Blog/blob/main/Images/QuasarRAT/Heavy%20Obfuscation%20and%20Chinese.png)

It's very obfuscated and in Chinese...

I have heard of [De4dot](https://github.com/de4dot/de4dot) for deobfuscation and found that it was already part of FlareVM so decided to throw it at De4dot.
De4dot came back with "Detected Unknown Obfuscator", I am starting to wonder if the use of Chinese is throwing it off.

![De4dot](https://github.com/W4llyw/Blog/blob/main/Images/QuasarRAT/De4dot%20uknown.png)

I did some more research into other .net deobfuscation tools and came across another .net deobfuscator and unpacker [NETReactorSlayer](https://github.com/SychicBoy/NETReactorSlayer?tab=readme-ov-file).I really need to go through all the installed tools on FlareVM because checking FlareVM and NETReactorSlayer is also already installed, but honestly who has the time for that.
Alright lets see what this thing can do, I checked all options and threw in the malware because why not.

![Slaying](https://github.com/W4llyw/Blog/blob/main/Images/QuasarRAT/Slaying.png)

Once NETReactorSlayer was done it produced a deobfuscated version of the exe with _Slayed appended to it(I renamed that one to just _QuasarRat_slayed.exe). It also unpacked a slew of dlls it must use at runtime which explains the low amount of imports seen earlier in PeStudio.

![Slayed&Dlls](https://github.com/W4llyw/Blog/blob/main/Images/QuasarRAT/Slayed%20w%20dll.png)

Looking at the sample again in dnSpy it is no longer in Chinese, but still obfuscated.

![English&Obfuscated](https://github.com/W4llyw/Blog/blob/main/Images/QuasarRAT/English%20but%20obfuscated.png)

I wondered why the namespaces and classes were still gibberish after NetReactorSlayer had deobfuscated and unpacked it. And I am pretty sure it is due to code virtualization.Basically code virtualization converts your code into randomized instructions that are interpreted at runtime. This technique seems to be extremely difficult to reverse and most people just go with the crazy names or change them as they come across them. If you want to know more about code virtualization you can look [here](https://www.eziriz.com/help/definitions/code_virtualization/#example-usage).

As you may have noticed in one of the earlier screenshots there are a lot of namespaces in this application.

![Assembly list](https://github.com/W4llyw/Blog/blob/main/Images/QuasarRAT/assembly%20list.png)

Luckily I know just were to start: the entry point.

![EntryPoint](https://github.com/W4llyw/Blog/blob/main/Images/QuasarRAT/Entry%20Point.png)

Now based off of my previous experiances with malware I knew that early on it needs to decrypt its configuration so it can act on them and continue functioning. Although I couldn't really read what the names of the classes were I did what I would call a "walk" of them. I simply went down the entry point class by class until one led me to a list of items being decrypted. And thats exactly where class `e4VF3YgDwO0iB` led me.

![Walking the Entrypoint](https://github.com/W4llyw/Blog/blob/main/Images/QuasarRAT/Walking%20the%20entry%20point.png)

![Finding the Goods](https://github.com/W4llyw/Blog/blob/main/Images/QuasarRAT/Finding%20the%20goods.png)

I have been in this situation before and knew exactly what to do, set a break point.

![Breakpoint](https://github.com/W4llyw/Blog/blob/main/Images/QuasarRAT/Break%20Point%20set.png)

With the breakpoint set I hit debug(`F5`) opened the static fields window and there it was. Instantly what looks like a C2 IP with port number and the name and location of where the malware runs from once executed.

![The Reveal](https://github.com/W4llyw/Blog/blob/main/Images/QuasarRAT/The%20Reveal.png)

We will see what all we can do with this info soon, but now I want to move on to see what all this thing is trying to do. After running up to the break point all the unpacked dlls are loaded. One that stuck out to me was called `Pulsar.Common.dll` once expanded, it looks like all the malicious functions of this malware come from this one dll.

![Pulsar1](https://github.com/W4llyw/Blog/blob/main/Images/QuasarRAT/Pulsar.png)
![Pulsar2](https://github.com/W4llyw/Blog/blob/main/Images/QuasarRAT/Pulsar2.png)

Looking at these namespaces you can clearly see that this thing is capable of just about everything in the book. It's gathering info its changing registry keys and doing something called `Pulsar.Common.Messages.FunStuff` doing what could be some ransomware tactics.

![FunStuff](https://github.com/W4llyw/Blog/blob/main/Images/QuasarRAT/funstuff.png)

