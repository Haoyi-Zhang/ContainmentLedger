"""Draw the two containment examples directly in Python; no TeX or network.

Requires Python 3.9+ and Matplotlib. These are explanatory graphs, not measurements.
"""
import argparse
from pathlib import Path
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.patches import Rectangle, Polygon, Circle, FancyArrowPatch

plt.rcParams.update({'font.family':'STIXGeneral', 'mathtext.fontset':'stix',
                     'font.size':9, 'pdf.fonttype':42, 'ps.fonttype':42,
                     'text.usetex':False, 'axes.unicode_minus':False})
CM = 1 / 2.54

class Drawing:
    def __init__(self, bounds):
        x0,y0,x1,y1 = bounds
        self.fig = plt.figure(figsize=((x1-x0)*CM,(y1-y0)*CM))
        self.ax = self.fig.add_axes([0,0,1,1], xlim=(x0,x1), ylim=(y0,y1))
        self.ax.set_aspect('equal'); self.ax.axis('off')
        self.nodes = {}
        self.labels = []

    def text(self,x,y,label,size=9,ha='center',va='center'):
        artist=self.ax.text(x,y,label,fontsize=size,ha=ha,va=va,
                            linespacing=1.15,clip_on=False,zorder=4)
        self.labels.append([artist,None])
        return artist

    def box(self,name,x,y,w,h,label,dashed=False,shape='rect',size=9):
        style = {'edgecolor':'black','facecolor':'white','linewidth':.55,
                 'linestyle':(0,(4,3)) if dashed else 'solid', 'zorder':2}
        if shape == 'diamond':
            obj = Polygon([(x-w/2,y),(x,y+h/2),(x+w/2,y),(x,y-h/2)],**style)
        elif shape == 'circle': obj = Circle((x,y),w/2,**style)
        else: obj = Rectangle((x-w/2,y-h/2),w,h,**style)
        self.ax.add_patch(obj); self.text(x,y,label,size)
        self.labels[-1][1]=(x-w/2,y-h/2,x+w/2,y+h/2)
        self.nodes[name] = (x,y,w,h,shape)

    def point(self,name,side):
        x,y,w,h,_ = self.nodes[name]
        return {'n':(x,y+h/2),'s':(x,y-h/2),'e':(x+w/2,y),
                'w':(x-w/2,y),'nw':(x-w/2,y+h/2),
                'ne':(x+w/2,y+h/2),'c':(x,y)}[side]

    def line(self,points,dashed=False):
        xs,ys=zip(*points)
        self.ax.plot(xs,ys,color='black',linewidth=.55,
                     linestyle=(0,(4,3)) if dashed else 'solid',zorder=1)

    def arrow(self,p,q,dashed=False,via=()):
        points=[p,*via,q]
        if via:self.line(points[:-1],dashed)
        self.ax.add_patch(FancyArrowPatch(points[-2],points[-1],
                         arrowstyle='-|>',mutation_scale=7.5,linewidth=.55,
                         color='black',shrinkA=0,shrinkB=0,
                         linestyle=(0,(4,3)) if dashed else 'solid',zorder=1))

    def edge(self,a,b,sa='s',sb='n',**kwargs):
        self.arrow(self.point(a,sa),self.point(b,sb),**kwargs)

    def frame(self,x,y,w,h):
        self.ax.add_patch(Rectangle((x,y),w,h,fill=False,edgecolor='black',
                                   linewidth=.55,linestyle=(0,(4,3)),zorder=0))

    def save(self,out,name):
        # Fixed physical canvas: do not enlarge or rasterize the scientific figure.
        self.fig.canvas.draw()
        renderer=self.fig.canvas.get_renderer()
        x0,x1=self.ax.get_xlim();y0,y1=self.ax.get_ylim()
        for artist,node in self.labels:
            b=artist.get_window_extent(renderer).transformed(self.ax.transData.inverted())
            if b.x0<x0-.02 or b.x1>x1+.02 or b.y0<y0-.02 or b.y1>y1+.02:
                raise ValueError(name+': clipped label '+repr(artist.get_text()))
            if node and (b.x0<node[0]-.02 or b.x1>node[2]+.02 or b.y0<node[1]-.02 or b.y1>node[3]+.02):
                raise ValueError(name+': label exceeds node '+repr(artist.get_text()))
        self.fig.savefig(out/(name+'.pdf'),format='pdf',
                         metadata={'Creator':'Python Matplotlib','Producer':None,
                                   'CreationDate':None,'ModDate':None})
        plt.close(self.fig)





def draw(out):
    d=Drawing((-.8,-2.3,5.3,1.18))
    for name,x in [('x',0),('y',2.25),('z',4.5)]:
        d.box(name,x,0,.78,.54,'$'+name+'$')
    d.ax.add_patch(Rectangle((4.5-.39-.04,-.27-.04),.86,.62,
                            fill=False,edgecolor='black',linewidth=.55,zorder=2))
    d.edge('x','y','e','w');d.edge('y','z','e','w')
    d.text(1.125,.28,'rewrite',8.5);d.text(3.375,.28,'rewrite',8.5)
    d.ax.add_patch(Rectangle((-.68,-.83),5.86,1.66,fill=False,
                            edgecolor='black',linewidth=.55,zorder=0))
    d.text(2.25,.97,'locally checked shard',8.5)
    d.box('new',2.25,-1.65,1.0,.54,"$y':\\mathsf{B}$")
    d.ax.add_patch(FancyArrowPatch(d.point('new','n'),d.point('y','s'),
        arrowstyle='<|-|>',mutation_scale=7.5,linewidth=.55,color='black',
        shrinkA=0,shrinkB=0,linestyle=(0,(4,3)),zorder=1))
    d.text(2.5,-1.05,'equal canonical code',8.5,ha='left')
    d.text(2.25,-2.10,'new trusted root',8.5)
    d.save(out,'late-alias')

    d=Drawing((-.35,-1.4,4.35,1.4))
    d.box('s',0,0,.45,.45,'$s$',shape='circle')
    d.box('t',4,0,.45,.45,'$t$',shape='circle')
    for j,y in [(1,1.05),(2,0),(3,-1.05)]:
        name='v'+str(j);d.box(name,2,y,.45,.45,'$v_'+str(j)+'$',shape='circle')
        for source,target,label,x in [('s',name,'$a$',1),(name,'t','$z_'+str(j)+'$',3)]:
            sx,sy,*_=d.nodes[source];tx,ty,*_=d.nodes[target]
            dx,dy=tx-sx,ty-sy;norm=(dx*dx+dy*dy)**.5
            d.arrow((sx+.225*dx/norm,sy+.225*dy/norm),
                    (tx-.225*dx/norm,ty-.225*dy/norm))
            d.text(x,y/2+(.20 if j!=3 else -.20),label)
    d.save(out,'grouped-cut')

if __name__=="__main__":
    parser=argparse.ArgumentParser()
    parser.add_argument("--output",type=Path,default=Path(__file__).resolve().parent)
    out=parser.parse_args().output
    out.mkdir(parents=True,exist_ok=True)
    draw(out)
