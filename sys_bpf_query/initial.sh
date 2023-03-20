sudo rm initial.text
sudo cat /proc/kallsyms | grep sys_call_table >> initial.text
sudo cat /proc/kallsyms | grep prog_idr >> initial.text
sudo cat /proc/kallsyms | grep link_idr >> initial.text
