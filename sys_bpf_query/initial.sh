sudo rm initial.text
sudo cat /proc/kallsyms | grep sys_call_table | head -n 1 >> initial.text
sudo cat /proc/kallsyms | grep prog_idr | head -n 1 >> initial.text
sudo cat /proc/kallsyms | grep link_idr | head -n 1 >> initial.text
