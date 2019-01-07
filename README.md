# Sezzer

Sezzer is a binary only software testing framework targets linux binaries and analyze for memory bugs that takes advantages from both dynamic concolic execution and greybox fuzzing for better code coverage and target specific vulnerability discovery.

We evaluation showed that with benchmark binaries, SEZZER is able to achieve an average of more than 50% more node coveragecomparing to several other software testing tools. With Lava-M test suite, SEZZER is able to find all the inserted vulnerabilities in 3 out of 4 binaries in a short amount of time, and exploited 2076 out of 2163 vulnerabilities of the 4th binary in a 24 hour run. We also found several bugs in master branch of GNU-binutils that leads to 5 patches and 3 CVEs.

Comparing with pure AFL on coreutils, Sezzer improves the node coverage for 19.3% on average and decreased coverage by a small margin on only 6 of the binaries.
![coreutils](https://github.com/gz-thesis/sezzer/raw/master/test/test.png)
<img src="https://github.com/gz-thesis/sezzer/raw/master/test/test.png" width="440" height="280">


For the benchmark binaries that are widely used by other tools, The result showed that comparing to the best performer other than Sezzer, our framework achieved more than 130% more coverage on 2 of the binaries (nm and objdump), around 30% 50% more coverage on 5 of the binaries (mutool, xmllint, cxxfilt, readelf and tcpdump), 13% more coverage on one binary (djpeg)
and 9% less coverage on 1 binary(readpng).
![benchmark binaries](https://github.com/gz-thesis/sezzer/raw/master/test/bench.png)
<img src="https://github.com/gz-thesis/sezzer/raw/master/test/bench.png" width="440" height="280">

The result of Lava-M test suite experiment showed that for three out of the four binaries, Sezzer is not only able to
find all the vulnerabilities established, but also able to trigger crashes that are not listed
by the authors of LAVA, and for who, Sezzer is able to find 2076 out of 2136 crashes.
![LAVA-M](https://github.com/gz-thesis/sezzer/raw/master/test/lava.png)
<img src="https://github.com/gz-thesis/sezzer/raw/master/test/lava.png" width="440" height="280">


# Installation

Sezzer is composed of four major parts and one optional component:

 - [America fuzzy lop (AFL)](http://lcamtuf.coredump.cx/afl/)
 - A modified version of [S2E](https://github.com/s2e)
 - [Postgres database](https://github.com/postgres/postgres)
 - (Optional) A modified version of [pgadmin](https://github.com/postgres/pgadmin4) to monitor the overall testing progress
 - Sezzer core

To setup the working environment, first clone the repository to your local machine with
```sh
$ export SEZZER_HOME="~/sezzer"
$ git clone https://github.com/gz-thesis/sezzer.git $SEZZER_HOME
```


Since all the components are set up and executed inside their own docker containers, docker is required to be set up first.
#### setup docker
Follow the instructions of [Get Docker CE for Ubuntu](https://docs.docker.com/install/linux/docker-ce/ubuntu/)

#### 


#### setup postgres and (optional)pgadmin4
```sh
$ cd $SEZZER_HOME/postgres
$ bash postgresql.docker
```
and follow the prompts.

#### setup AFL
```sh
$ cd $SEZZER_HOME/afl/Dockerfile
$ docker build -t cim_fuzz .
```

#### setup S2E
```sh
$ cd /tmp
$ git clone https://github.com/gz-thesis/s2e-mod.git
$ cd s2e-mod && mkdir build && cd build && make -f ../Makefile install
$ cp /tmp/s2e-mod/build/opt/* $SEZZER_HOME/s2e/build/ -r
```

#### S2E VM images
```sh
$ cd /tmp
$ # x86_64 image
$ wget https://drive.google.com/open?id=1fybAk4Qb-0Ig8W3immpwBLc-SZoN7UUh -O debian-9.2.1-x86_64.tar.xz
$ tar -xf debian-9.2.1-x86_64.tar.xz
$ cp -r debian-9.2.1-x86_64 $SEZZER_HOME/s2e/images
$ # i386 image
$ wget https://drive.google.com/open?id=1RltZ99RXk4dnP8XHAldVyCgUcliDTplY -O debian-9.2.1-i386.tar.xz
$ tar -xf debian-9.2.1-i386.tar.xz
$ cp -r debian-9.2.1-i386 $SEZZER_HOME/s2e/images
```


# Run
For detailed usage information, you can try
```bash
$ cd $SEZZER_HOME
$ python ./cimfuzz.py --help
```

or you can try:
```
$ cd $SEZZER_HOME
$ python ./cimfuzz.py run\
         --uri ./test/readelf_x86_64.tar.gz \
         --timeout_s2e 600 \
         --s2e_check_interval 20 \
         --s2e_launch_threshold 10 \
         --host 127.0.0.1 \
         --port 5432 \
         --num_afl 14 \
         --num_s2e 2 \
         --num_master 0 
```
to test the readelf binary and start from there.
