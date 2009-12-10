                     Kdump check STONITH plugin "kdumpcheck"
1. Introduction
    This plugin's purpose is to avoid STONITH for a node which is doing kdump.
    It confirms whether the node is doing kdump or not when STONITH reset or
    off operation is executed.
    If the target node is doing kdump, this plugin considers that STONITH
    succeeded. If not, it considers that STONITH failed.

    NOTE: This plugin has no ability to shutdown or startup a node.
          So it has to be used with other STONITH plugin.
          Then, when this plugin failed, the next plugin which can kill a node
          is executed.
    NOTE: This plugin works only on Linux.

2. The way to check
   When STONITH reset or off is executed, kdumpcheck connects to the target
   node, and checks the size of /proc/vmcore.
   It judges that the target node is _not_ doing kdump when the size of
   /proc/vmcore on the node is zero, or the file doesn't exist.
   Then kdumpcheck returns "STONITH failed" to stonithd, and the next plugin
   is executed.

3. Expanding mkdumprd
    This plugin requires non-root user and ssh connection even on 2nd kernel.
    So, you need to apply mkdumprd_for_kdumpcheck.patch to /sbin/mkdumprd.
    This patch is tested with mkdumprd version 5.0.39.
    The patch adds the following functions:
      i) Start udevd with specified .rules files.
     ii) Bring the specified network interface up.
    iii) Start sshd.
     iv) Add the specified user to the 2nd kernel.
         The user is to check whether the node is doing kdump or not.
      v) Execute sync command after dumping.

     NOTE: i) to iv) expandings are only for the case that filesystem partition
           is specified as the location where the vmcore should be dumped.

4. Parameters
    kdumpcheck's parameters are the following.
      hostlist     : The list of hosts that the STONITH device controls.
                     delimiter is "," or " ".
                     indispensable setting. (default:none)
      identity_file: a full-path of the private key file for the user
                     who checks doing kdump.
                     (default: $HOME/.ssh/id_rsa, $HOME/.ssh/id_dsa and
                               $HOME/.ssh/identity)

    NOTE: To execute this plugin first, set the highest priority to this plugin
          in all STONITH resources.

5. How to Use
    To use this tool, do the following steps at all nodes in the cluster.
      1) Add an user to check doing kdump.
         ex.)
           # useradd kdumpchecker
           # passwd kdumpchecker
      2) Allow passwordless login from the node which will do STONITH to all
         target nodes for the user added at step 1).
         ex.)
           $ cd
           $ mkdir .ssh
           $ chmod 700 .ssh
           $ cd .ssh
           $ ssh-keygen (generate authentication  keys with empty passphrase)
           $ scp id_rsa.pub kdumpchecker@target_node:"~/.ssh/."
           $ ssh kdumpchecker@target_node
           $ cd ~/.ssh
           $ cat id_rsa.pub >> authorized_keys
           $ chmod 600 autorized_keys
           $ rm id_rsa.pub
      3) Limit the command that the user can execute.
         Describe the following commands in a line at the head of the user's
         public key in target node's authorized_keys file.
         [command="test -s /proc/vmcore"]
         And describe some options (like no-pty, no-port-forwarding and so on)
         according to your security policy.
         ex.)
           $ vi ~/.ssh/authorized_keys
           command="test -s /proc/vmcore",no-port-forwarding,no-X11-forwarding,
           no-agent-forwarding,no-pty ssh-rsa AAA..snip..== kdumpchecker@node1
      4) Add settings in /etc/kdump.conf.
           network_device   : network interface name to check doing kdump.
                              indispensable setting. (default: none)
           kdump_check_user : user name to check doing kdump.
                              specify non-root user.
                              (default: "kdumpchecker")
           udev_rules       : .rules files' names.
                              specify if you use udev for mapping devices.
                              specified files have to be in /etc/udev/rules.d/.
                              you can specify two or more files.
                              delimiter is "," or " ". (default: none)
         ex.)
           # vi /etc/kdump.conf
           ext3 /dev/sda1
           network_device eth0
           kdump_check_user kdumpchecker
           udev_rules 10-if.rules
      5) Apply the patch to /sbin/mkdumprd.
           # cd /sbin
           # patch -p 1 < mkdumprd_for_kdumpcheck.patch
      6) Restart kdump service.
           # service kdump restart
      7) Describe cib.xml to set STONITH plugin.
         (See "2. Parameters" and "6. Appendix")

6. Appendix
    A sample cib.xml.
    <clone id="clnStonith">
      <instance_attributes id="instance_attributes.id238245a">
        <nvpair id="clone0_clone_max" name="clone_max" value="2"/>
        <nvpair id="clone0_clone_node_max" name="clone_node_max" value="1"/>
      </instance_attributes>
      <group id="grpStonith">
        <instance_attributes id="instance_attributes.id2382455"/>
        <primitive id="grpStonith-kdumpcheck" class="stonith" type="external/kd
    umpcheck">
          <instance_attributes id="instance_attributes.id238240a">
            <nvpair id="nvpair.id238240b" name="hostlist" value="node1,node2"/>
            <nvpair id="nvpair.id238240c" name="priority" value="1"/>
          <nvpair id="nvpair.id2382408b" name="stonith-timeout" value="30s"/>
          </instance_attributes>
          <operations>
            <op id="grpStonith-kdumpcheck-start" name="start" interval="0"  tim
    eout="300" on-fail="restart"/>
            <op id="grpStonith-kdumpcheck-monitor" name="monitor" interval="10"
     timeout="60" on-fail="restart"/>
            <op id="grpStonith-kdumpcheck-stop" name="stop" interval="0" timeou
    t="300" on-fail="block"/>
          </operations>
          <meta_attributes id="primitive-grpStonith-kdump-check.meta"/>
        </primitive>
        <primitive id="grpStonith-ssh" class="stonith" type="external/ssh">
          <instance_attributes id="instance_attributes.id2382402a">
            <nvpair id="nvpair.id2382408a" name="hostlist" value="node1,node2"/
    >
            <nvpair id="nvpair.id238066b" name="priority" value="2"/>
            <nvpair id="nvpair.id2382408c" name="stonith-timeout" value="60s"/>
          </instance_attributes>
          <operations>
            <op id="grpStonith-ssh-start" name="start" interval="0" timeout="30
    0" on-fail="restart"/>
            <op id="grpStonith-ssh-monitor" name="monitor" interval="10" timeou
    t="60" on-fail="restart"/>
            <op id="grpStonith-ssh-stop" name="stop" interval="0" timeout="300"
     on-fail="block"/>
          </operations>
          <meta_attributes id="primitive-grpStonith-ssh.meta"/>
        </primitive>
      </group>
    </clone>

