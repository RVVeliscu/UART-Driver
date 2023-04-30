# Guide for using the test infrastructure

## Setup
1. Login into your gitlab accout using the UPB login at https://gitlab.cs.pub.ro/users/sign_in
2. Make a **private** fork of this repository.
In the right corner you can find the fork button.
After clicking it, the following should be prompted at you:

![private_fork](./img/private_fork.png)

Select your user as the namespace for your fork.
And please make sure the visibility level is set to **Private**

3. Clone your repo locally
```
$ git clone <remote_of_your_private_fork>
```

## Working on the assignment
Start the assignment from the header inside the `src/` directory.
Please note that you must provide a `Kbuild` file and the module name must be `uart16550.ko`.
> **Warning**
> You must not change this header, it will be overwritten by the checker. 
> You can include any other headers in your project.

The first option is to code in the `src/` and run the checker using the following command:
```
$ ./local.sh checker 2-uart
```
This will start the docker, start the SO2 VM inside the docker and run the checher for you inside the VM.
If your run on Linux you can add the `--privileged` argument to the previous command and the checker will run with KVM support.

The second and recommended option is to connect to the docker interactively and then to the VM and run the checker manually.
1. Connect to the docker
```
$ ./local.sh docker interactive
```
If you use native Linux you can benefit from KVM superpowers using the `--privileged` argument.
Thus the container will be started in privileged mode and you have access to KVM.
After executing the last command you should get a prompter in the docker.

> **Warning**
> When running in interactive mode the `src/` directory is mounted to the `/linux/tools/labs/skels/assignments/2-uart` directory inside the docker.
> The previous directory is shared with the VM as well in `skels/assignments/2-uart`.
> So any change in one  would affect the other.
> **Be careful not to delete your code!**.
> We encourage you to make as many commits as possible on your **private** gitlab repo!

2. Build your assignment:
```
# you should be in /linux/tools/labs inside the docker
$ make build
```

3. You can start the VM with the following command:
```
# you should be in /linux/tools/labs inside the docker
$ make console
```
After this command you should get a prompter inside the VM
To exit from the VM, you can use the following key combination:
```
CTRL + A X
```

4. Copy the `*.ko` into the `skels/assginments/2-uart-checker` directory
```
# you should be in /home/root inside the VM
$ cd skels/assignments/2-uart-checker
$ cp ../2-uart/uart16550.ko .
# If you cannot find the solution.ko symlink in the checker directory
# you should also copy the solution.ko from the _test directory
# this module is part of the checker
$ cp  _test/solution.ko .
```

5. Run the checker
```
# you should be in skels/assignments/2-uart-checker inside the VM
sh _checker
```

## Submiting the assignment
1. Create a `*.zip` archive containing all the source files and headers of your solution and a `Kbuild` file that results in the `uart16550.ko` module.
> **Warning**
> Please, keep in mind that you are not allowed to change the header inside the `/src` directory (`vmchecker-next` will overwrite this file, along with others).
> Also, make sure the sources are in the **root of the archive**.
2. Upload the archive on moodle in the section corresponding to the assignment.
3. After a few minutes, you can see the checker results on the submission page, like in the following image.
> **Warning**
> Please make sure you get the score as feedback on the moodle page. Otherwise, something wrong happened in the checker and the assignment will not be graded.

![feedback](./img/feedback.png)

Find the complete procedure for using `vmchecker-next` [here](https://github.com/systems-cs-pub-ro/vmchecker-next/wiki/Student-Handbook)

> **Warning**
> Although there is an alternative way to submit your assignment please submit the archive directly.
