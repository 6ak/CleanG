


#include "lteCore.h"

void corePrint2 (void){
  printf ("core print%i",ALIDEBUG);
}



void addGTPUHeader(struct rte_mbuf* pkt, uint32_t teid)
{
  struct GTPUHeader *gh;
  gh = (struct GTPUHeader *)rte_pktmbuf_prepend(pkt, sizeof(struct GTPUHeader));
  gh->teid = teid;
  return;
}




void  printOutputEnb(FILE* f, struct timespec* startTimes_t,struct timespec* startTimes_a,struct timespec* startTimes_i,struct timespec* startTimes_d,struct timespec* startTimes_h, 
    struct timespec* hstartTimes_t,struct timespec* hstartTimes_a,struct timespec* hstartTimes_i,struct timespec* hstartTimes_d,struct timespec* hstartTimes_h
    , struct timespec* endTimes_t,struct timespec* endTimes_a,struct timespec* endTimes_i,struct timespec* endTimes_d,struct timespec* endTimes_h, 
    struct timespec* hendTimes_t,struct timespec* hendTimes_a,struct timespec* hendTimes_i,struct timespec* hendTimes_d,struct timespec* hendTimes_h
    ){


  int j;
  for (j=0; j < USER_STATE_SIZE; j++)
  {
    //fprintf(f, "userID %d, startnano %ld endnano %ld startsec %ld endsec %ld\n", j, startTimes[j].tv_nsec, endTimes[j].tv_nsec, startTimes[j].tv_sec, endTimes[j].tv_sec);

    fprintf(f, "userID %d ", j);
    fprintf(f, "start_n_t %ld end_n_t %ld  start_s_t %ld end_s_t %ld ", startTimes_t[j].tv_nsec, endTimes_t[j].tv_nsec, startTimes_t[j].tv_sec, endTimes_t[j].tv_sec);
    fprintf(f, "start_n_a %ld end_n_a %ld  start_s_a %ld end_s_a %ld ", startTimes_a[j].tv_nsec, endTimes_a[j].tv_nsec, startTimes_a[j].tv_sec, endTimes_a[j].tv_sec);
    fprintf(f, "start_n_i %ld end_n_i %ld  start_s_i %ld end_s_i %ld ", startTimes_i[j].tv_nsec, endTimes_i[j].tv_nsec, startTimes_i[j].tv_sec, endTimes_i[j].tv_sec);
    fprintf(f, "start_n_d %ld end_n_d %ld  start_s_d %ld end_s_d %ld ", startTimes_d[j].tv_nsec, endTimes_d[j].tv_nsec, startTimes_d[j].tv_sec, endTimes_d[j].tv_sec);
    fprintf(f, "start_n_h %ld end_n_h %ld  start_s_h %ld end_s_h %ld ", startTimes_h[j].tv_nsec, endTimes_h[j].tv_nsec, startTimes_h[j].tv_sec, endTimes_h[j].tv_sec);
    if (endTimes_t[j].tv_sec != 0) {
      fprintf(f, "t_value %ld ", (startTimes_t[j].tv_sec == endTimes_t[j].tv_sec ? endTimes_t[j].tv_nsec - startTimes_t[j].tv_nsec : endTimes_t[j].tv_nsec - startTimes_t[j].tv_nsec + 1000000000));
    } else {
      fprintf(f, "t_value %d ", 0);
    }
    if (endTimes_a[j].tv_sec != 0) {
      fprintf(f, "a_value %ld ", (startTimes_a[j].tv_sec == endTimes_a[j].tv_sec ? endTimes_a[j].tv_nsec - startTimes_a[j].tv_nsec : endTimes_a[j].tv_nsec - startTimes_a[j].tv_nsec + 1000000000));
    } else {
      fprintf(f, "a_value %d ", 0);
    }
    if (endTimes_i[j].tv_sec != 0) {
      fprintf(f, "i_value %ld ", (startTimes_i[j].tv_sec == endTimes_i[j].tv_sec ? endTimes_i[j].tv_nsec - startTimes_i[j].tv_nsec : endTimes_i[j].tv_nsec - startTimes_i[j].tv_nsec + 1000000000));
    } else {
      fprintf(f, "i_value %d ", 0);
    }
    if (endTimes_d[j].tv_sec != 0 ) {
      fprintf(f, "d_value %ld ", (startTimes_d[j].tv_sec == endTimes_d[j].tv_sec ? endTimes_d[j].tv_nsec - startTimes_d[j].tv_nsec : endTimes_d[j].tv_nsec - startTimes_d[j].tv_nsec + 1000000000));
    } else {
      fprintf(f, "d_value %d ", 0);
    }
    if (endTimes_h[j].tv_sec != 0) {
      fprintf(f, "h_value %ld ", (startTimes_h[j].tv_sec == endTimes_h[j].tv_sec ? endTimes_h[j].tv_nsec - startTimes_h[j].tv_nsec : endTimes_h[j].tv_nsec - startTimes_h[j].tv_nsec + 1000000000));
    }
    else 
    {
      fprintf(f, "h_value %d ", 0);
    }
    fprintf(f, "\n");



  }
  for (j=0; j < NUMBER_OF_USERS; j++)
  {
    //fprintf(f, "userID %d, startnano %ld endnano %ld startsec %ld endsec %ld\n", j, hstartTimes[j].tv_nsec, hendTimes[j].tv_nsec, hstartTimes[j].tv_sec, hendTimes[j].tv_sec);

    fprintf(f, "userID %d ", j);
    fprintf(f, "start_n_t %ld end_n_t %ld  start_s_t %ld end_s_t %ld ", hstartTimes_t[j].tv_nsec, hendTimes_t[j].tv_nsec, hstartTimes_t[j].tv_sec, hendTimes_t[j].tv_sec);
    fprintf(f, "start_n_a %ld end_n_a %ld  start_s_a %ld end_s_a %ld ", hstartTimes_a[j].tv_nsec, hendTimes_a[j].tv_nsec, hstartTimes_a[j].tv_sec, hendTimes_a[j].tv_sec);
    fprintf(f, "start_n_i %ld end_n_i %ld  start_s_i %ld end_s_i %ld ", hstartTimes_i[j].tv_nsec, hendTimes_i[j].tv_nsec, hstartTimes_i[j].tv_sec, hendTimes_i[j].tv_sec);
    fprintf(f, "start_n_d %ld end_n_d %ld  start_s_d %ld end_s_d %ld ", hstartTimes_d[j].tv_nsec, hendTimes_d[j].tv_nsec, hstartTimes_d[j].tv_sec, hendTimes_d[j].tv_sec);
    fprintf(f, "start_n_h %ld end_n_h %ld  start_s_h %ld end_s_h %ld ", hstartTimes_h[j].tv_nsec, hendTimes_h[j].tv_nsec, hstartTimes_h[j].tv_sec, hendTimes_h[j].tv_sec);
    if (hendTimes_t[j].tv_sec != 0) {
      fprintf(f, "t_value %ld ", (hstartTimes_t[j].tv_sec == hendTimes_t[j].tv_sec ? hendTimes_t[j].tv_nsec - hstartTimes_t[j].tv_nsec : hendTimes_t[j].tv_nsec - hstartTimes_t[j].tv_nsec + 1000000000));
    } else {
      fprintf(f, "t_value %d ", 0);
    }
    if (hendTimes_a[j].tv_sec != 0) {
      fprintf(f, "a_value %ld ", (hstartTimes_a[j].tv_sec == hendTimes_a[j].tv_sec ? hendTimes_a[j].tv_nsec - hstartTimes_a[j].tv_nsec : hendTimes_a[j].tv_nsec - hstartTimes_a[j].tv_nsec + 1000000000));
    } else {
      fprintf(f, "a_value %d ", 0);
    }
    if (hendTimes_i[j].tv_sec != 0) {
      fprintf(f, "i_value %ld ", (hstartTimes_i[j].tv_sec == hendTimes_i[j].tv_sec ? hendTimes_i[j].tv_nsec - hstartTimes_i[j].tv_nsec : hendTimes_i[j].tv_nsec - hstartTimes_i[j].tv_nsec + 1000000000));
    } else {
      fprintf(f, "i_value %d ", 0);
    }
    if (hendTimes_d[j].tv_sec != 0 ) {
      fprintf(f, "d_value %ld ", (hstartTimes_d[j].tv_sec == hendTimes_d[j].tv_sec ? hendTimes_d[j].tv_nsec - hstartTimes_d[j].tv_nsec : hendTimes_d[j].tv_nsec - hstartTimes_d[j].tv_nsec + 1000000000));
    } else {
      fprintf(f, "d_value %d ", 0);
    }
    if (hendTimes_h[j].tv_sec != 0) {
      fprintf(f, "h_value %ld ", (hstartTimes_h[j].tv_sec == hendTimes_h[j].tv_sec ? hendTimes_h[j].tv_nsec - hstartTimes_h[j].tv_nsec : hendTimes_h[j].tv_nsec - hstartTimes_h[j].tv_nsec + 1000000000));
    }
    else 
    {
      fprintf(f, "h_value %d ", 0);
    }
    fprintf(f, "\n");
  }
  return;
}
