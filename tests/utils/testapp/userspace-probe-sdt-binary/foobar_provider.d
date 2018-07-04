provider foobar {
    probe tp1();
    probe tp2();
    probe tp_in_shared_object();
    probe tp_in_dlopen();
    probe tp_in_ldpreload();
    probe tp_with_arg(int);
    probe tp_with_semaphore();
};
