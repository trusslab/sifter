go run gen_tracer.go -config ../syzkalls/src/github.com/google/syzkaller/configs/adb_binder.cfg -dev controlC0 -fd fd_sndctrl -entry snd_ctl_ioctl -out snd_ctl
