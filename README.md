# DLL-loading-sequence-hijacking-static-heuristic-detection
该启发特征的思想来源于看雪学院的姜晔，非常感谢姜晔老师的指导。
该DLL静态启发式检测，使用三个特征分别为: 有三个导出函数地址相同、有三个函数大小相同地址相邻、导出函数名相同。
文件当中有一部分被注释掉的代码，是关于验证文件数字签名的。数字签名检验的代码部分有问题，所以注释掉了。
由于许多正常的DLL文件也会被上述启发特征所匹配。
所以必须要完善关于验证数字签名的代码，以降低误报率。
但是关于验证数字签名的代码的部分，有一些暂时没有解决的问题。


使用：输入一个文件夹路径，自动扫描该文件夹内的所有DLL（32位DLL）

The idea of this enlightening feature comes from jiang ye, who is in xue college. Thanks for your guidance.
The DLL static heuristic detection, the use of three characteristics are: there are three exported function address the same, there are three functions of the same size address adjacent, exported function name the same.
There is a part of the code that is commented out in the file, which is about verifying the digital signature of the file. There is a problem with the code part of digital signature verification, so it is commented out.
Since many normal DLL files will also be matched by the above heuristic features.
Therefore, it is necessary to improve the code about verifying digital signature to reduce the false alarm rate.
But there are some unresolved issues with the part of the code that verifies digital signatures.


Use: enter a folder path and automatically scan all DLLS in the folder（32-bit DLL）
