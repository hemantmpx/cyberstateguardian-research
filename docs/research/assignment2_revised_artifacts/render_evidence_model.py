"""Research diagram: three distinct claims in endpoint evidence reconciliation."""
from pathlib import Path
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch

OUT=Path(__file__).resolve().parent/'figures'
OUT.mkdir(exist_ok=True)

def render():
    blue, orange, ink, green='#1b4965','#a84f2a','#25313a','#3c735c'
    plt.rcParams.update({'font.family':'DejaVu Sans','svg.fonttype':'none','pdf.fonttype':42})
    fig,ax=plt.subplots(figsize=(7.25,2.55))
    ax.set_xlim(0,100); ax.set_ylim(0,36); ax.axis('off')
    def box(x,y,w,h,title,body,edge,fill):
        ax.add_patch(FancyBboxPatch((x,y),w,h,boxstyle='round,pad=0.25,rounding_size=1',linewidth=.9,edgecolor=edge,facecolor=fill))
        ax.text(x+w/2,y+h-2.2,title,ha='center',va='top',fontsize=8.4,fontweight='bold',color=edge)
        ax.text(x+w/2,y+h/2-1,body,ha='center',va='center',fontsize=7.3,color=ink,linespacing=1.45)
    def arrow(start,end,label=None,rad=0):
        ax.add_patch(FancyArrowPatch(start,end,arrowstyle='-|>',mutation_scale=8,linewidth=.9,color='#657480',connectionstyle=f'arc3,rad={rad}'))
        if label:
            ax.text((start[0]+end[0])/2,(start[1]+end[1])/2+.8,label,ha='center',fontsize=6.7,color='#59666e')
    for x,text in [(14,'1  OBSERVE'),(50,'2  ASSOCIATE'),(84,'3  FINALIZE / REVISE')]:
        ax.text(x,35,text,ha='center',fontsize=8.5,fontweight='bold',color=ink)
    box(1,18,27,13,'State assertion','Native before/after object state\nChange observed over [t1, t2]',blue,'#edf3f7')
    box(1,2.5,27,13,'Event evidence','Wazuh alerts + archives\nSource event time ≠ receipt time',orange,'#fbf0e9')
    box(38,10,25,15,'Exact eligibility','Host · full object · operation\nObservation interval ± tolerance\nTransition value, when available',ink,'#f5f6f7')
    box(38,26.7,25,7.1,'Coverage & health','',green,'#edf4ee')
    ax.text(50.5,27.9,'Collection · query completeness',ha='center',fontsize=6.6,color=green)
    box(74,14,25,15,'Versioned outcome','CONSISTENT: exact evidence\nPENDING: opportunity open\nUNEXPLAINED: requirement unmet',blue,'#edf3f7')
    arrow((28.3,24.5),(37.4,20)); arrow((28.3,9),(37.4,14))
    arrow((50.5,26.4),(50.5,25.4)); arrow((63.4,17.5),(73.4,20),'grace')
    arrow((96,13.6),(77,13.6),rad=-.4)
    ax.text(84.5,8.0,'Late evidence: retain v1, add v2',ha='center',fontsize=6.7,color='#59666e')
    ax.text(50.5,5.7,'Empty query ≠ failed collection',ha='center',fontsize=7.2,color=ink)
    ax.text(84.5,2.8,'Corroboration ≠ causality or authorization',ha='center',fontsize=7.1,color=ink)
    fig.subplots_adjust(left=.01,right=.99,top=.96,bottom=.05)
    for ext in ['png','svg','pdf']:
        fig.savefig(OUT/f'figure1_evidence_model.{ext}',dpi=450,bbox_inches='tight',facecolor='white')
    plt.close(fig)

if __name__=='__main__': render()
