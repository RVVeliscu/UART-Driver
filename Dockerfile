FROM gitlab.cs.pub.ro:5050/so2/so2-assignments

RUN echo "Hello from Docker"
RUN mkdir -p /linux/tools/labs/skels/assignments/2-uart
RUN mkdir -p /linux/tools/labs/skels/assignments/2-uart-checker

COPY ./checker/checker_daemons/so2_vm_checker_daemon.sh /linux/tools/labs/rootfs/etc/init.d
RUN chmod +x /linux/tools/labs/rootfs/etc/init.d/so2_vm_checker_daemon.sh
RUN chroot /linux/tools/labs/rootfs update-rc.d so2_vm_checker_daemon.sh defaults

