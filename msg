[4mmsgget[24m(2)                                                          System Calls Manual                                                         [4mmsgget[24m(2)

[1mNAME[0m
       msgget - get a System V message queue identifier

[1mLIBRARY[0m
       Standard C library ([4mlibc[24m, [4m-lc[24m)

[1mSYNOPSIS[0m
       [1m#include <sys/msg.h>[0m

       [1mint msgget(key_t [4m[22mkey[24m[1m, int [4m[22mmsgflg[24m[1m);[0m

[1mDESCRIPTION[0m
       The  [1mmsgget[22m()  system call returns the System V message queue identifier associated with the value of the [4mkey[24m argument.  It may be used either to
       obtain the identifier of a previously created message queue (when [4mmsgflg[24m is zero and [4mkey[24m does not have the value [1mIPC_PRIVATE[22m), or to create a new
       set.

       A new message queue is created if [4mkey[24m has the value [1mIPC_PRIVATE [22mor [4mkey[24m isn't [1mIPC_PRIVATE[22m, no message queue with the given  key  [4mkey[24m  exists,  and
       [1mIPC_CREAT [22mis specified in [4mmsgflg[24m.

       If  [4mmsgflg[24m specifies both [1mIPC_CREAT [22mand [1mIPC_EXCL [22mand a message queue already exists for [4mkey[24m, then [1mmsgget[22m() fails with [4merrno[24m set to [1mEEXIST[22m.  (This
       is analogous to the effect of the combination [1mO_CREAT | O_EXCL [22mfor [1mopen[22m(2).)

       Upon creation, the least significant bits of the argument [4mmsgflg[24m define the permissions of the message queue.  These  permission  bits  have  the
       same format and semantics as the permissions specified for the [4mmode[24m argument of [1mopen[22m(2).  (The execute permissions are not used.)

       If a new message queue is created, then its associated data structure [4mmsqid_ds[24m (see [1mmsgctl[22m(2)) is initialized as follows:

       •  [4mmsg_perm.cuid[24m and [4mmsg_perm.uid[24m are set to the effective user ID of the calling process.

       •  [4mmsg_perm.cgid[24m and [4mmsg_perm.gid[24m are set to the effective group ID of the calling process.

       •  The least significant 9 bits of [4mmsg_perm.mode[24m are set to the least significant 9 bits of [4mmsgflg[24m.

       •  [4mmsg_qnum[24m, [4mmsg_lspid[24m, [4mmsg_lrpid[24m, [4mmsg_stime[24m, and [4mmsg_rtime[24m are set to 0.

       •  [4mmsg_ctime[24m is set to the current time.

       •  [4mmsg_qbytes[24m is set to the system limit [1mMSGMNB[22m.

       If the message queue already exists the permissions are verified, and a check is made to see if it is marked for destruction.

[1mRETURN VALUE[0m
       On  success, [1mmsgget[22m() returns the message queue identifier (a nonnegative integer).  On failure, -1 is returned, and [4merrno[24m is set to indicate the
       error.

[1mERRORS[0m
       [1mEACCES [22mA message queue exists for [4mkey[24m, but the calling process does not have permission to access the queue, and does not have the  [1mCAP_IPC_OWNER[0m
              capability in the user namespace that governs its IPC namespace.

       [1mEEXIST IPC_CREAT [22mand [1mIPC_EXCL [22mwere specified in [4mmsgflg[24m, but a message queue already exists for [4mkey[24m.

       [1mENOENT [22mNo message queue exists for [4mkey[24m and [4mmsgflg[24m did not specify [1mIPC_CREAT[22m.

       [1mENOMEM [22mA message queue has to be created but the system does not have enough memory for the new data structure.

       [1mENOSPC [22mA message queue has to be created but the system limit for the maximum number of message queues ([1mMSGMNI[22m) would be exceeded.

[1mSTANDARDS[0m
       POSIX.1-2008.

[1mHISTORY[0m
       POSIX.1-2001, SVr4.

   [1mLinux[0m
       Until Linux 2.3.20, Linux would return [1mEIDRM [22mfor a [1mmsgget[22m() on a message queue scheduled for deletion.

[1mNOTES[0m
       [1mIPC_PRIVATE [22misn't a flag field but a [4mkey_t[24m type.  If this special value is used for [4mkey[24m, the system call ignores everything but the least signif‐
       icant 9 bits of [4mmsgflg[24m and creates a new message queue (on success).

       The following is a system limit on message queue resources affecting a [1mmsgget[22m() call:

       [1mMSGMNI [22mSystem-wide  limit  on  the  number of message queues.  Before Linux 3.19, the default value for this limit was calculated using a formula
              based on available system memory.  Since Linux 3.19, the default value is 32,000.  On Linux, this limit  can  be  read  and  modified  via
              [4m/proc/sys/kernel/msgmni[24m.

[1mBUGS[0m
       The name choice [1mIPC_PRIVATE [22mwas perhaps unfortunate, [1mIPC_NEW [22mwould more clearly show its function.

[1mSEE ALSO[0m
       [1mmsgctl[22m(2), [1mmsgrcv[22m(2), [1mmsgsnd[22m(2), [1mftok[22m(3), [1mcapabilities[22m(7), [1mmq_overview[22m(7), [1msysvipc[22m(7)

Linux man-pages 6.8                                                    2024-05-02                                                              [4mmsgget[24m(2)
