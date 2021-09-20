# Testing Web Vulnerabilities 


## Command Injection

According to [OWASP's](https://owasp.org/www-community/attacks/Command_Injection) website:

> *Command Injection* is an attack in which the goal is execution of arbitrary commands on the host operating system via a vulnerable application. *Command injection* attacks are possible when an application passes unsafe user supplied data (forms, cookies, HTTP headers etc.) to a system shell. In this attack, the attacker-supplied operating system commands are usually executed with the privileges of the vulnerable application. Command injection attacks are possible largely due to insufficient input validation.


### Using DVWA 

The Damn Vulnerable Web App is an Open Source Project for a PHP/MySQL web application that is damn vulnerable, the code can be found at [digininja's Github](https://github.com/digininja/DVWA). As explained in its website the goals are to be an aid for security professionals or web developers to better understand the processes of securing and exploiting web applications. More importantly, this is a **legal** way to explore these kind of vulnerabilities. Remember never to try this in applications where you don't have explicit permission to do so.

In my setup I'm running the DVWA in a Docker container inside an Ubutu VM.

![DVWA Welcome Page](Images/Command_Injection/DVWA_Main.PNG)


1. Open the DVWA in your browser and select **Command Injection** from the left-hand side Menu. 

    ![DVWA Welcome Page](Images/Command_Injection/DVWA_command_injection.PNG)


2. In this page the intended use is to allow the users to ping any IP address that they enter into the textbox. For example if a user writes `8.8.8.8` and then they click *Submit*, the application would ping that IP address (Note: `8.8.8.8` is Google's IP).

    ![DVWA Welcome Page](Images/Command_Injection/DVWA_command_injection_PING.PNG)

3. The next step is to try to manipulate the input:
    - Writing just a command like `pwd` (print working directory) does not seem to work.
    - Writing `8.8.8.8 && pwd` on the other hand, changes the results. This would mean that the application is vulnerable to *Command Injection*, and since `pwd` is a Linux command, this would mean that the application is running on Linux.
    ![DVWA Welcome Page](Images/Command_Injection/DVWA_command_injection_PING_PWD.PNG)
    - Since the application runs on Linux, we could try to get something tastier, like the contents of `/etc/passwd` and `/etc/hosts`. 
    - To get the contents of those files, we can use the dot-dot-slash method to move to other directories.
         - Input:  `-c 1 10.0.0.1; pwd && cat ../../../../../etc/passwd`
         - Results: Contents of the file are shown in the screen.
          ![DVWA Welcome Page](Images/Command_Injection/DVWA_CommandInjection_passwd.PNG)
         - Input:  `-c 1 10.0.0.1; pwd && cat ../../../../../etc/hosts`
         - Results: Contents of the file are shown in the screen.
          ![DVWA Welcome Page](Images/Command_Injection/DVWA_CommandInjection_hosts.PNG)
4. Mitigations:
    - Validate user input client-side and server-side, so just one IP address can be submitted by the user and no other commands can be added.
    - Set permissions in the server, so the web user has no access to confidential files (principle of least privilege).




