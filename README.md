# beep_shellcode
Beep shellcode written in pure C (x86 intel)

#Use cases
Easy preparing shellcode in c

#Algorithm
1. Write base independent code. 2. Save it in section 'shell' of PE-image. 3. Dump this section to disc. 4. Load shellcode from disc and run it in memory.