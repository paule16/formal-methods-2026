1. Open this directory in VSCode

2. Create Python environment

   1. Open any .py file in editor
   
   2. Install Python extensions which will be suggested
   
   3. Create virtual environment with installing dependencies
      (right-bottom corner)

3. Allow using of sudo:

   1. Make current user capabilities of sudoers:
   
       sudo usermod -G sudo <current user>

   2. Allow of sudo without password for current user:

       sudo visudo
       add line to the end: <current user> ALL=(ALL:ALL) NOPASSWD:ALL

4. Install utilities depedencies:

   sudo apt install podman

5. Make base image:

   make -C testing/base_image
