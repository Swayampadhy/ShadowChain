# ShadowChain

Shadow Chain is a modular DRM enabled dll injector with capabilities of Anti-debugging and persistence. 
For implementation details, visit -> https://swayampadhy.gitbook.io/root/projects/shadowchain

# Features Of ShadowChain

1. Digital Rights Management(DRM) using volume serial number of the machine
2. Anti-debugging usig TLS Callbacks
3. IAT Camoflague
4. Remote process Dll Injection
5. Persistence using Startup Folder

# How to Execute

1. Replace payload code in "payload.c" in payload project with your desired payload.
2. Compile both ShadowChain and payload
3. Execute on machine
4. Profit!!

# Results

1. Initial run of ShadowChain
   
   ![image](https://github.com/user-attachments/assets/652b0586-59a6-40a7-a61f-e95828baad48)

2. Subsequent Runs Of ShadowChain in Same machine
   
   ![image](https://github.com/user-attachments/assets/21911d7b-466a-4a67-aaab-bce7eff2b6b6)

3. When the same binary is run under a different machine
   
   ![image](https://github.com/user-attachments/assets/b9da053d-f336-4f08-b07d-6986f7d9add1)

4. Main function being nulled out when debugger is detected
   
   ![image](https://github.com/user-attachments/assets/56cf39ad-87b7-4ca0-a98c-e296b8521d46)

5. Shadowchain persisting in startup folder after execution
    
   ![image](https://github.com/user-attachments/assets/3fea32ca-7d73-4ac2-bf2d-aa2837f4382b)
