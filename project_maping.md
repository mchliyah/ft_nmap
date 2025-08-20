1. parce config ip port and type
   - port range if multiple (0 - 1024 default )
   - scan types default SYN 
   - ip target must be set or looping from file
2. starting  a thread litner which will catch respences form target
   - sending correct packet with corect packet triger server to respond and so 
     the listner parce packet to define the port targetet (OPEN, CLOSE, ...)
3. sending packets to triger the server target (based on  speedup value max 250)
   - default speedup value set to 0 , in this case the programe will use one thread
     to send all ports targeted
   - speedup make ports deviding by thread (200 port to scan with 10 speedup example ) 
     -> 2 ports per thread to send 
{to seabch later if we may create many listners to procces packets sens the listner will procces recived packets } 