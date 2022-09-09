# Sifter
Sifter generates syscall tracers and filters for kernel modules automatically. It utilizes Syzkaller's syscall description and generates an eBPF/tracepoints tracer that logs syscalls along with their arguments. After analyzing the trace, seccomp/eBPF filters are generated to limit untrusted programs' syscall usage, which includes their argument values and the sequences. Currently, the prototype is implemented and tested on Google Pixel 3.

## Device setup
To try Sifter on a Google Pixel 3, first, you will need to compile and install the customized Android and kernel.

### Installing AOSP
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
./extract-google_devices-blueline.sh
```
``` bash
./extract-qcom-blueline.sh
```
Patch AOSP to support tracers and filters generated by Sifter. The patch files can be found in sifter/patches/
``` bash
cd bionic && git apply <sifter>/patches/bionic.patch && cd ../
```
``` bash
cd system/bpf && git apply <sifter>/patches/system_bpf.patch && cd ../../
```
Compile AOSP
``` bash
source build/envsetup.sh
```
``` bash
lunch aosp_blueline-userdebug
```
``` bash
m
```
Enter recovery mode by pressing and holding power + volume down bottons and then flash the device
``` bash
fastboot flashall -w
```
After the flash prociess finishes, reboot the phone and check if it succeeds
``` bash
fastboot reboot
```


### Installing kernel
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
git remote add sifter https://github.com/trusslab/sifter_kernel.git
```
``` bash
git fetch sifter master
```
``` bash
git checkout sifter/master
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
After the compilation, push the new kernel modules to the device first in case the device becomes unauthenticated in adb and the touch screen does not work with the old kernel modules.
``` bash
adb push out/android-msm-pixel-4.9/dist/*.ko /vendor/lib/modules/
```
In blueline-aosp directory. Generate and flash the new boot.img
``` bash
cp blueline-kernel/out/android-msm-pixel-4.9/dist/Image.lz4 ./device/google/crosshatch-kernel/Image.lz4
```
``` bash
m bootimage
```
Enter recovery mode again by either pushing the power and volume down buttons or using the command
``` bash
adb reboot bootloader
```
Before actually flashing the new boot.img, try to boot the device with the new boot.img first to see if the new kernel works correctly
``` bash
fastboot boot out/target/product/blueline/boot.img
```
Then, flash boot.img and reboot the device
``` bash
fastboot flash boot out/target/product/blueline/boot.img
```
``` bash
fastboot reboot
```
Now the device is able to run tracers and filters generated by filter.

## Using Sifter

### Installing Syzkaller
Since Sifter leverages Syzkaller's syscall description to automatically generate tracers and filters, you will need to install Syzkaller before running Sifter's tracer/filter generator.

Follow the [guide](https://github.com/google/syzkaller/blob/master/docs/linux/setup_linux-host_qemu-vm_arm64-kernel.md) to compile and install Syzkaller

### Generating tracers using Sifter
``` bash
git clone https://github.com/trusslab/sifter.git
```
``` bash
cd sifter
```
In Sifter's directory, generate the eBPF/tracepoints tracer by running the following command
``` bash
go run sifter_v2.go -mode tracer -config ../syzkalls/src/github.com/google/syzkaller/configs/adb_binder.cfg -fd fd_kgsl -out kgsl
```
In the default output directory, gen/, you will find the generated source code for the eBPF tracer (e.g., linux\_arm64\_kgsl.c) and a configuration file you will need later for the agent to load the corresonding tracer (e.g., linux\_arm64\_kgsl\_agent.cfg)

### Compiling tracers and the agent
In blueline-asop, create sifter-kern for compiling eBPF tracers and filters
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
In blueline-aosp, copy and compile the user-space agent
``` bash
cp -r <sifter>/agent external/ && cd external/agent
```
Compile the agent
``` bash
mm
```

### Running tracer
Push the tracer and agent to the device
``` bash
adb push blueline-aosp/out/target/product/blueline/system/etc/bpf/linux_arm64_xxx.o /etc/bpf/
```
``` bash
adb shell mkdir /data/sifter
```
``` bash
adb push blueline-aosp/out/target/product/blueline/system/bin/agent /data/sifter/
```
``` bash
adb push <sifter>/gen/linux_arm64_xxx_agent.cfg /data/sifter/
```
Reboot the device and the tracer will be loaded automatically during boot. You can check if the tracer is being loaded successfully by
``` bash
adb logcat -s bpfloader
```
To start tracing syscalls of user programs, execute the agent, which will attach the eBPF tracer to the tracepoint hook and log the syscalls of the target program specified by its 16-charater-long command (<comm> can be found by running cat /proc/<pid>/comm). Now you can execute the target program in another terminal. The agent will store the results to the output file periodically. Note that if the output file already exist, the agent will restore the result from it at the beginning.
``` bash
adb shell /data/sifter/agent -c <agent configuration file> -p <comm> -o <output file>
```

## Analyzing traces and generating filters
After the desired trace is collected, you can analyze and generate eBPF/seccomp filters by feed the trace to sifter again by
``` bash
go run sifter.go -mode filter -config ../syzkalls/src/github.com/google/syzkaller/configs/adb_binder.cfg -fd fd_kgsl -out kgsl
```
