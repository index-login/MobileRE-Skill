set confirm off
set pagination off
set auto-solib-add off
target remote 127.0.0.1:5039
echo --- Register Dump (aarch64) ---\n
info registers x0 x1 x2 x3 x4 x5 x29 x30 sp pc
echo \n--- Read 64 bytes from PC ---\n
x/8gx $pc
echo \n--- Thread List ---\n
info threads
echo \n--- Detaching (process resumes) ---\n
detach
quit