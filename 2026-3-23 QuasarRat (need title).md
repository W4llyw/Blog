# Title


I was looking for my next journey into malware analysis and this time around I decided to take a look at QuasarRat. It's a .net based RAT that is a bit more complicated than AsyncRAT and seemed to have been favored by Advanced Persistent Threats (APT) based out of china for awhile. According to an article posted by [Huntress](https://www.huntress.com/threat-library/threat-actors/apt10) parts of the APT (APT10) group were indicted in 2018. This made me interested in why or who is still using it today and possibly exposing their infrastructure, lets see what we can find out.

### Finding the sample
As usual getting malware from the internet is never difficult. By using MalwareBazaar's search syntax `signature:QuasarRAT` I pulled up all the posted malware with the QuasarRAT signature. Since it was sorted by latest posted I chose the first one that showed up and just went for it.

**Take Caution When Downloading From Any Site That Hosts Malware as These Are Live Samples**

![MalwareBazaar](https://github.com/W4llyw/Blog/blob/main/Images/QuasarRAT/Bazaar.png)

### Initial look with Tools
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

It's very obfuscated and partially in Chinese...
