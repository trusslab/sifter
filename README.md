# Sifter
Sifter generates syscall tracers and filters for kernel components automatically. The eBPF/kprobes tracer monitors syscalls and generates the policy, which can be used by the seccomp/eBPF filter to limit untrusted applications' syscall patterns. Currently, the prototype is implemented and tested on Google Pixel 3.

## Prepare device
Download AOSP source
``` bash
mkdir blueline-aosp && cd blueline-aosp
```
``` bash
repo init -u https://android.googlesource.com/platform/manifest -b android-10.0.0_r15
```
``` bash
repo sync
```
Download and extract vendor binaries
``` bash
wget https://dl.google.com/dl/android/aosp/google_devices-blueline-qq1a.191205.008-8c723695.tgz
```
``` bash
wget https://dl.google.com/dl/android/aosp/qcom-blueline-qq1a.191205.008-5932f083.tgz 
```
``` bash
tar zxvf google_devices-blueline-qq1a.191205.008-8c723695.tgz
```
``` bash
tar zxvf qcom-blueline-qq1a.191205.008-5932f083.tgz
```
``` bash
extract-google_devices-blueline.sh
```
``` bash
extract-qcom-blueline.sh
```
Compile the kernel
``` bash
source build/envsetup.sh
```
``` bash
lunch aosp_blueline-userdebug
```
``` bash
m
```
Enter the recovery mode and flash the device
``` bash
fastboot flashall -w
```
After the flash process finishes, reboot the phone and check if it succeeds
``` bash
fastboot reboot
```

Now we download the AOSP kernel for Pixel 3, patch it and flash the boot.img
``` bash
mkdir blueline-kernel && cd blueline-kernel
```
``` bash
repo init -u https://android.googlesource.com/kernel/manifest -b android-msm-crosshatch-4.9-android10-qpr1
```
``` bash
repo sync
```
Get Sifter's modified kernel
``` bash
cd private/msm-google
```
``` bash
git remote set-url sifter https://github.com/trusslab/sifter_kernel.git
```
``` bash
git fetch sifter
```
``` bash
cd ../../
```
Modify build.config and compile the kernel
```
function update_nocfi_config() {
  # Disable clang-specific options
  ${KERNEL_DIR}/scripts/config --file ${OUT_DIR}/.config \
    -e CONFIG_KASAN \
    -e CONFIG_KCOV \
    -e CONFIG_KCOV_ENABLE_COMPARISONS \
    -e CONFIG_SLUB \
    -e CONFIG_SECCOMP_FILTER_EXTENDED \
    -e CONFIG_FAULT_INJECTION \
    -e CONFIG_FAULT_INJECTION_DEBUG_FS \
    -e CONFIG_FAILSLAB \
    -e CONFIG_FAIL_PAGE_ALLOC \
    -e CONFIG_FAIL_MAKE_REQUEST \
    -e CONFIG_FAIL_IO_TIMEOUT \
    -e CONFIG_FAIL_FUTEX \
    -d CONFIG_KASAN_OUTLINE \
    -d CONFIG_RANDOMIZE_BASE \
    -d CONFIG_CC_WERROR \
    --set-val CONFIG_FRAME_WARN 0 \
    -d LTO \
    -d LTO_CLANG \
    -d CFI \
    -d CFI_PERMISSIVE \
    -d CFI_CLANG \
    -d SHADOW_CALL_STACK
  (cd ${OUT_DIR} && \
    make O=${OUT_DIR} $archsubarch CROSS_COMPILE=${CROSS_COMPILE} olddefconfig)
}
```
``` bash
./build/build.sh
```
After the compilation, push the new kernel modules to the device first in case the device becomes unauthenticated and the touch screen does not repond with the old kernel modules.
``` bash
adb push out/android-msm-pixel-4.9/dist/*.ko /vendor/lib/modules/
```
Generate and flash the new boot.img
``` bash
cp out/android-msm-pixel-4.9/dist/Image.lz4 ../blueline-aosp/device/google/crosshatch-kernel/Image.lz4
```
Switch to blueline-aosp
``` bash
m bootimage
```
Enter recovery mode again by either pushing the power and volume down buttons or using the command
``` bash
adb reboot bootloader
```
Before actually flashing the new boot.img, you can try to boot with the new boot.img first to see if the new one is working correctly
``` bash
fastboot boot out/target/product/blueline/boot.img
```
Then you can flash the boot.img with
``` bash
fastboot flash boot out/target/product/blueline/boot.img
```
``` bash
fastboot reboot
```

## Install Syzkaller
Since Sifter leverages Syzkaller's syscall description to automatically generate tracers and filters, you will need to install Syzkaller before running Sifter's tracer/filter generator.

Follow the [guide](https://github.com/google/syzkaller/blob/master/docs/linux/setup_linux-host_qemu-vm_arm64-kernel.md) to compile and install Syzkaller

## Use Sifter to generate tracer
``` bash
git clone https://github.com/trusslab/sifter.git
```
``` bash
cd sifter
```
In Sifter's directory, execute gen\_tracer.go and specify the configuration, resource name of the file descriptor in Syzkaller, syscall handler name in the kernel, and the output file name. For example,
``` bash
go run gen_tracer.go -config ../syzkalls/src/github.com/google/syzkaller/configs/adb_binder.cfg -fd fd_kgsl -entry kgsl_ioctl -out kgsl
```

## Compile tracers and the agent
In Sifter a tracer is responsible for tracing syscalls and generating the policy. It updates the eBPF map associated with the argument according to the datatype. An agent program associated to the tracer will be used to mount the tracer and read out the values stored in the maps.

In blueline-asop/externel, create sifter-kern for the eBPF tracers
``` bash
mkdir externel/sifter-kern && cd externel/sifter-kern
```
Copy the generated eBPF tracer, linux\_arm64\_xxx.c, to the current directory and create the makefile, Android.bp
```
bpf {
    name: "linux_arm64_xxx.o",
    srcs: ["linux_arm64_xxx.c"],
    cflags: [
        "-Wall",
        "-Werror",
    ],
}
```
Compile the tracer
``` bash
mm
```
In blueline-aosp/externel, create sifter-user for the agents
``` bash
mkdir externel/sifter-kern && cd externel/sifter-kern
```
Copy the generated eBPF agent, linux\_arm64\_xxx\_agent.c, to the current directory and create the makefile, Android.bp
```
cc_binary {
    name: "linux_arm64_xxx_agent",
    srcs: [
        "linux_arm64_xxx_agent.cpp"
        ],
    defaults: ["bpf_defaults"],
    shared_libs: [
        "libbpf_android",
        "libbpf",
        "libbase",
        "libnetdutils",
    ],
}

```
Compile the agent
``` bash
mm
```

## Run tracer
Push the tracer and agent to the device
``` bash
adb push blueline-aosp/out/target/product/blueline/system/etc/bpf/linux_arm64_xxx.o /etc/bpf/
```
``` bash
adb shell mkdir /data/local/sifter-agent
```
``` bash
adb push blueline-aosp/out/target/product/blueline/system/bin/linux_arm64_xxx_agent /data/local/sifter-agent
```
Reboot the device so that the tracer will be loaded automatically during boot. You can check if the tracer is being loaded successfully by
``` bash
adb logcat -s bpfloader
```
To start testing, execute the agent. It will mount the eBPF tracer to the kprobes hook, and the tracer will start tracing the syscall. Now you can execute any program in another terminal that will invoke the syscall. To stop, press any key and the result will be printed.
``` bash
adb shell /data/local/linux_arm64_xxx_agent
```
