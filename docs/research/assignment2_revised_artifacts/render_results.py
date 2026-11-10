"""Paper exhibits drawn from the saved metrics, with explicit units and denominators."""
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from render_evidence_model import render as render_model


def build_exhibits(here,norm,reg7,reg8,service,dwell,task,control,omission,omission3,lifecycle):
    figdir=here/'figures'
    blue,orange,green='#1b4965','#a84f2a','#3c735c'
    plt.rcParams.update({'font.family':'DejaVu Sans','font.size':8,
        'axes.spines.top':False,'axes.spines.right':False,'svg.fonttype':'none','pdf.fonttype':42})
    render_model()
    def save(fig,name):
        for ext in ('png','pdf','svg'):
            fig.savefig(figdir/f'{name}.{ext}',dpi=450,bbox_inches='tight',facecolor='white')
        plt.close(fig)
    curve=dwell['pooled_dwell_capture']
    fig,ax=plt.subplots(figsize=(3.55,3.05))
    x=[r['planned_dwell_seconds'] for r in curve]
    y=[r['rate']*100 for r in curve]
    lo=[p-100*r['wilson_95_interval'][0] for p,r in zip(y,curve)]
    hi=[100*r['wilson_95_interval'][1]-p for p,r in zip(y,curve)]
    ax.axvline(5,ls=':',color='#8a969d',lw=1)
    ax.text(4.4,23,'5 s polling',rotation=90,color='#657480',fontsize=7,ha='right')
    ax.errorbar(x,y,yerr=[lo,hi],fmt='o-',color=blue,markersize=5,capthick=1,capsize=3,lw=1.6,label='Combined: 20 trials per dwell')
    for ci,scale,marker,label in [(0,.96,'s','Cohort 1: 10 trials'),(1,1.04,'^','Extension: 10 trials')]:
        ax.scatter([v*scale for v in x],[r['cohort_results'][ci]['rate']*100 for r in curve],marker=marker,s=23,facecolors='white',edgecolors=blue,zorder=4,label=label)
    ax.plot(x,[100]*4,'--',color=green,lw=1.3,label='Exact events retrieved later')
    for xx,yy,r in zip(x,y,curve):
        ax.annotate(f"{r['captured']}/{r['trials']}",(xx,yy),xytext=(0,8 if yy<90 else -17),textcoords='offset points',ha='center',fontsize=8,fontweight='bold')
    ax.set_xscale('log',base=2);ax.set_xlim(.20,15);ax.set_ylim(-5,113)
    ax.set_xticks(x,['0.25','2','6','12']);ax.set_yticks([0,25,50,75,100])
    ax.set_xlabel('Automatic-mode dwell (s; log-spaced axis)')
    ax.set_ylabel('Exact target transition observed (%)')
    ax.grid(axis='y',color='#e5e8ea',lw=.7)
    ax.legend(loc='upper center',bbox_to_anchor=(.5,-.22),fontsize=7,frameon=False,ncol=2,columnspacing=.8,handlelength=1.4)
    fig.subplots_adjust(left=.17,right=.98,top=.96,bottom=.30)
    save(fig,'figure2_complementary_visibility')

    cohorts=lifecycle['cohorts']
    fig,axes=plt.subplots(3,1,figsize=(3.55,4.15),gridspec_kw={'height_ratios':[1,1,1.65]})
    def dots(ax,values,row,color):
        # Fixed jitter exposes repeated measurements; no random/statistical resampling.
        offsets=[-.13,-.09,-.05,0,.05,.09,.13,-.10,.03,.10]
        ax.scatter(values,[row+offsets[i] for i in range(len(values))],s=16,color=color,alpha=.72,zorder=3)
        median=sorted(values)[len(values)//2] if len(values)%2 else sum(sorted(values)[len(values)//2-1:len(values)//2+1])/2
        ax.plot([median,median],[row-.23,row+.23],color=color,lw=2.4,zorder=4)
        return median
    for ax,metric,title,limit in [
        (axes[0],'action_to_probe_category_sample_seconds','A  Action → native category sample',(0,24)),
        (axes[1],'bounded_trial_query_client_duration_seconds','B  Narrow trial query duration',(0,3.4))]:
        labels=[]
        for row,key,color in [(0,'v2',blue),(1,'v3',orange)]:
            vals=[r['intervals_seconds'][metric] for r in cohorts[key]['trial_rows'] if r['intervals_seconds'][metric] is not None]
            med=dots(ax,vals,row,color)
            labels.append(f'{key} (n=10)\nmedian {med:.1f} s')
        ax.set_yticks([0,1],labels,fontsize=7.2);ax.set_ylim(1.45,-.45)
        ax.set_xlim(*limit);ax.set_title(title,loc='left',fontsize=8.2,fontweight='bold',pad=6)
        ax.set_xlabel('Seconds',fontsize=7.5);ax.grid(axis='x',color='#e5e8ea',lw=.7)
    ax=axes[2]
    labels=[]
    for row,key,metric,color,label in [
        (0,'v2','evidence_deadline_to_first_final_seconds',blue,'v2 first (n=9)'),
        (1,'v2','evidence_deadline_to_latest_final_seconds',green,'v2 latest (n=9)'),
        (2,'v3','evidence_deadline_to_first_final_seconds',orange,'v3 first/latest (n=10)')]:
        vals=[r['intervals_seconds'][metric]/60 for r in cohorts[key]['trial_rows'] if r['intervals_seconds'][metric] is not None]
        med=dots(ax,vals,row,color)
        labels.append(label+f'\nmedian {med:.1f} min')
    ax.set_yticks([0,1,2],labels,fontsize=7)
    ax.set_ylim(2.5,-.5);ax.set_xscale('log');ax.set_xlim(.6,155)
    ax.set_xticks([1,10,100],['1','10','100'])
    ax.set_title('C  Evidence deadline → finalized version',loc='left',fontsize=8.2,fontweight='bold',pad=6)
    ax.set_xlabel('Minutes after deadline (log scale)',fontsize=7.5)
    ax.grid(axis='x',color='#e5e8ea',lw=.7)
    fig.subplots_adjust(left=.31,right=.99,top=.95,bottom=.10,hspace=1.05)
    save(fig,'figure3_lifecycle_clocks')
    tables={
      'TABLE_1':{'caption':'TABLE I. Evidence sources and their inferential role',
       'headers':['Evidence','Unit / size','What it measures'],
       'rows':[
        ['Windows-APT V3','102,011 events; 36 catalogue scenarios','Normalization; behavior selection'],
        ['Registry Oct. 7 / 8','Two separate 30-window cohorts','Complete / omission / no action'],
        ['Paired services','20 live targets; six methods','State visibility and wrong attribution'],
        ['Task controls','10 distractor + 10 no-action windows','Exact association; stable state'],
        ['Task omission v2 / v3','Separate 10-target cohorts','Linked findings; history-based timing'],
        ['Service dwell','Two cohorts × 50 trials','Duration-dependent sampling'],
        ['Derived validation','90 registry + 60 task rows; 21 fixtures','Fixed-parent invariants; not new trials']],
       'note':'All live cohorts share one endpoint. Replay rows reuse captured parents. Post-hoc task audits retain the original controller dispositions.',
       'widths':[.28,.34,.38]},
      'TABLE_2':{'caption':'TABLE II. Cross-plane outcomes in separate live controls',
       'headers':['Condition (n=10 each)','Native state','Exact Wazuh','Final record'],
       'rows':[
        ['Registry: complete','10/10','10/10','C: 10/10'],
        ['Registry: omission + wrong object','10/10','0/10','U: 10/10'],
        ['Registry: no action','No change','N/A','FF: 0/10'],
        ['Task: complete + wrong object','10/10','10/10','C: 10/10'],
        ['Task: no action','No change','N/A','FF: 0/10'],
        ['Task omission v2','10/10','0/10','U: 9/10'],
        ['Task omission v3†','10/10','0/10','U: 10/10†']],
       'note':'Registry rows are Oct. 7 V3; Oct. 8 repeats are separate in text. C = CONSISTENT; U = UNEXPLAINED; FF = false finding. Task omission outcomes are post-run audits. †Controller gaps remain. Wilson intervals: 10/10, 72.2%–100%; 9/10, 59.6%–98.2%; 0/10, 0%–27.8%.',
       'widths':[.41,.18,.17,.24]},
      'TABLE_3':{'caption':'TABLE III. Same-trial service comparison (20 targets)',
       'headers':['Method','Measured target evidence','False attribution','Final U'],
       'rows':[
        ['Configured Wazuh alert/FIM','Creation event: 0/20','0/20','N/A'],
        ['Raw exact-event only','Creation event: 0/20','0/20','N/A'],
        ['Native probe only','Target state: 20/20','N/A','N/A'],
        ['Strong identity matcher','Creation event: 0/20','0/20','N/A'],
        ['Loose host/type/time','Wrong-object candidates: 20/20','20/20','N/A'],
        ['Full CSG','Target state: 20/20','0/20','20/20']],
       'note':'Identical captured event pool and cutoffs. Candidate emission is not correct target attribution. U = UNEXPLAINED. With no selected/supporting event, link precision/recall are undefined. Loose matching is an ablation; strong identity rejects equally well.',
       'widths':[.34,.31,.19,.16]},
    }
    captions={
      'FIGURE_1':'Fig. 1. The evidence contract separates observation, association, and decision history. Native state and Wazuh use separate paths on one host. Matching tolerance bounds source-time eligibility; grace governs receipt opportunity. Source/query health accompanies the outcome. Exact corroboration does not establish causality or authorization.',
      'FIGURE_2':'Fig. 2. Complementary visibility at five-second service polling. Combined counts are 0/20, 9/20, 19/20, and 20/20; bars are descriptive Wilson 95% intervals. Open markers retain each cohort; the extension followed first-cohort inspection. Dashed event coverage is later retrieval in 20/20 treatments per duration, not real-time arrival. No fitted threshold is asserted.',
      'FIGURE_3':'Fig. 3. Distinct lifecycle clocks: points are individual trials and vertical ticks are medians. Panel C separates first final decisions from later versions; v2 has one missing linked finding, excluded from timing but retained as failure. Sequential cohorts are not controlled speedup treatments. The v3 outcomes are post-hoc audited with controller gaps. Intervals are not additive pipeline stages.',
    }
    files={'FIGURE_1':'figure1_evidence_model','FIGURE_2':'figure2_complementary_visibility','FIGURE_3':'figure3_lifecycle_clocks'}
    return tables,captions,files
