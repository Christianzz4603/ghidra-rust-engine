//! CFG-aware SSA construction over P-code, including reaching definitions and phi nodes.
//! Memory spaces are deliberately not promoted; this first pass versions explicit varnodes.
use crate::intelligence::{ControlFlowGraph, FlowKind};
use crate::microcode::VarnodeIdentity;
use crate::program::{InstructionPcode, PcodeOperation};
use std::collections::{BTreeMap,BTreeSet};
#[derive(Clone,Copy,Debug,PartialEq,Eq,PartialOrd,Ord,Hash)] pub struct SsaVersion(pub u32);
#[derive(Clone,Debug,PartialEq,Eq)] pub struct SsaUse { pub variable:VarnodeIdentity,pub version:SsaVersion,pub input_index:usize }
#[derive(Clone,Debug,PartialEq,Eq)] pub struct SsaDefinition { pub variable:VarnodeIdentity,pub version:SsaVersion }
#[derive(Clone,Debug,PartialEq,Eq)] pub struct SsaPhi { pub variable:VarnodeIdentity,pub version:SsaVersion,pub incoming:Vec<(u64,SsaVersion)> }
#[derive(Clone,Debug,PartialEq,Eq)] pub struct SsaOperation { pub instruction_address:u64,pub operation_index:usize,pub uses:Vec<SsaUse>,pub definition:Option<SsaDefinition> }
#[derive(Clone,Debug,PartialEq,Eq)] pub struct SsaBlock { pub start:u64,pub phis:Vec<SsaPhi>,pub operations:Vec<SsaOperation> }
#[derive(Clone,Debug,Default,PartialEq,Eq)] pub struct SsaReport { pub blocks:Vec<SsaBlock>,pub variable_count:usize,pub definition_count:usize,pub phi_count:usize,pub iterations:usize,pub converged:bool }
#[derive(Clone,Copy,Debug,Default)] pub struct SsaAnalyzer;
#[derive(Clone)] struct OpRef { address:u64,index:usize,operation:PcodeOperation }
impl SsaAnalyzer {
 pub fn analyze(&self,cfg:&ControlFlowGraph,pcode:&[InstructionPcode])->SsaReport {
  let mut instruction_block=BTreeMap::<u64,u64>::new();
  for b in &cfg.blocks { for i in &b.instructions { instruction_block.insert(i.address,b.start); } }
  let mut ops_by_block=BTreeMap::<u64,Vec<OpRef>>::new(); let mut vars=BTreeSet::<VarnodeIdentity>::new();
  for i in pcode { if let Some(&start)=instruction_block.get(&i.address) { for (index,op) in i.operations.iter().enumerate() {
   for v in &op.inputs { if v.space!="const" {vars.insert(v.into());} }
   if let Some(v)=&op.output {if v.space!="const" {vars.insert(v.into());}}
   ops_by_block.entry(start).or_default().push(OpRef{address:i.address,index,operation:op.clone()});
  } } }
  let starts:BTreeSet<u64>=cfg.blocks.iter().map(|b|b.start).collect(); let mut preds=BTreeMap::<u64,BTreeSet<u64>>::new();
  for e in &cfg.edges { if e.kind==FlowKind::Call {continue;} if let Some(to)=e.to {if starts.contains(&e.from)&&starts.contains(&to){preds.entry(to).or_default().insert(e.from);}} }
  let mut next=1u32; let mut def_ids=BTreeMap::<(u64,u64,usize),SsaVersion>::new();
  for b in &cfg.blocks {if let Some(ops)=ops_by_block.get(&b.start){for op in ops {if op.operation.output.as_ref().is_some_and(|v|v.space!="const"){def_ids.insert((b.start,op.address,op.index),SsaVersion(next));next=next.saturating_add(1);}}}}
  let mut phi_ids=BTreeMap::<(u64,VarnodeIdentity),SsaVersion>::new();
  for b in &cfg.blocks {for v in &vars {phi_ids.insert((b.start,v.clone()),SsaVersion(next));next=next.saturating_add(1);}}
  let zero=SsaVersion(0); let initial:BTreeMap<_,_>=vars.iter().cloned().map(|v|(v,zero)).collect();
  let mut ins:BTreeMap<u64,BTreeMap<VarnodeIdentity,SsaVersion>>=cfg.blocks.iter().map(|b|(b.start,initial.clone())).collect();
  let mut outs=ins.clone(); let limit=cfg.blocks.len().saturating_mul(vars.len().saturating_add(1)).saturating_mul(4).max(8); let mut iterations=0;let mut converged=false;
  for _ in 0..limit {iterations+=1;let mut changed=false;for b in &cfg.blocks {
   let ps=preds.get(&b.start).cloned().unwrap_or_default();let mut incoming=BTreeMap::new();
   for v in &vars {let versions:BTreeSet<_>=ps.iter().filter_map(|p|outs.get(p).and_then(|s|s.get(v)).copied()).collect();let ver=if versions.len()>1{phi_ids[&(b.start,v.clone())]}else{versions.iter().next().copied().unwrap_or(zero)};incoming.insert(v.clone(),ver);}
   let mut outgoing=incoming.clone();if let Some(ops)=ops_by_block.get(&b.start){for op in ops {if let Some(v)=&op.operation.output {if v.space!="const" {if let Some(id)=def_ids.get(&(b.start,op.address,op.index)){outgoing.insert(v.into(),*id);}}}}}
   if ins.get(&b.start)!=Some(&incoming){ins.insert(b.start,incoming);changed=true;}if outs.get(&b.start)!=Some(&outgoing){outs.insert(b.start,outgoing);changed=true;}
  }if !changed{converged=true;break;}}
  let mut report=SsaReport{variable_count:vars.len(),definition_count:def_ids.len(),iterations,converged,..Default::default()};
  for b in &cfg.blocks {let ps=preds.get(&b.start).cloned().unwrap_or_default();let mut phis=Vec::new();
   for v in &vars {let incoming:Vec<_>=ps.iter().map(|p|(*p,outs.get(p).and_then(|s|s.get(v)).copied().unwrap_or(zero))).collect();let distinct:BTreeSet<_>=incoming.iter().map(|x|x.1).collect();if distinct.len()>1{phis.push(SsaPhi{variable:v.clone(),version:phi_ids[&(b.start,v.clone())],incoming});}}
   report.phi_count+=phis.len();let mut state=ins.get(&b.start).cloned().unwrap_or_default();let mut operations=Vec::new();
   if let Some(block_ops)=ops_by_block.get(&b.start){for op in block_ops {let uses=op.operation.inputs.iter().enumerate().filter_map(|(input_index,v)|{if v.space=="const"{return None;}let variable=VarnodeIdentity::from(v);Some(SsaUse{version:state.get(&variable).copied().unwrap_or(zero),variable,input_index})}).collect();
    let definition=op.operation.output.as_ref().and_then(|v|{if v.space=="const"{return None;}let variable=VarnodeIdentity::from(v);let version=def_ids.get(&(b.start,op.address,op.index)).copied()?;state.insert(variable.clone(),version);Some(SsaDefinition{variable,version})});
    operations.push(SsaOperation{instruction_address:op.address,operation_index:op.index,uses,definition});}}
   report.blocks.push(SsaBlock{start:b.start,phis,operations});
  }report
 }
}
#[cfg(test)] mod tests {
 use super::*;use crate::intelligence::{BasicBlock,Confidence,FlowEdge,FlowKind};use crate::opcodes::OpCode;use crate::program::{Instruction,PcodeOperation,PcodeVarnode};
 fn n(s:&str,o:u64)->PcodeVarnode{PcodeVarnode{space:s.into(),offset:o,size:8}}
 fn ins(a:u64)->Instruction{Instruction{address:a,length:4,bytes:vec![0;4],mnemonic:"nop".into(),operands:String::new()}}
 fn op(c:OpCode,out:Option<PcodeVarnode>,inputs:Vec<PcodeVarnode>)->PcodeOperation{PcodeOperation{opcode:c,output:out,inputs,space:None}}
 fn b(s:u64,as_:[u64;1])->BasicBlock{BasicBlock{start:s,end:s+4,instructions:vec![ins(as_[0])]}}
 fn e(a:u64,z:u64)->FlowEdge{FlowEdge{from:a,to:Some(z),kind:FlowKind::Branch,confidence:Confidence::Heuristic}}
 #[test]fn join_gets_phi_and_phi_version_reaches_use(){let cfg=ControlFlowGraph{function:0x100,blocks:vec![b(0x100,[0x100]),b(0x110,[0x110]),b(0x120,[0x120]),b(0x130,[0x130])],edges:vec![e(0x100,0x110),e(0x100,0x120),e(0x110,0x130),e(0x120,0x130)]};let pc=vec![InstructionPcode{address:0x110,length:4,operations:vec![op(OpCode::Copy,Some(n("register",1)),vec![n("const",7)])]},InstructionPcode{address:0x120,length:4,operations:vec![op(OpCode::Copy,Some(n("register",1)),vec![n("const",9)])]},InstructionPcode{address:0x130,length:4,operations:vec![op(OpCode::IntAdd,Some(n("register",2)),vec![n("register",1),n("const",1)])]}];let r=SsaAnalyzer.analyze(&cfg,&pc);let join=r.blocks.iter().find(|x|x.start==0x130).unwrap();assert_eq!(join.phis.len(),1);assert_eq!(join.operations[0].uses[0].version,join.phis[0].version);assert!(r.converged);}
 #[test]fn straight_line_definition_reaches_successor(){let cfg=ControlFlowGraph{function:0x100,blocks:vec![b(0x100,[0x100]),b(0x110,[0x110])],edges:vec![e(0x100,0x110)]};let pc=vec![InstructionPcode{address:0x100,length:4,operations:vec![op(OpCode::Copy,Some(n("register",1)),vec![n("const",3)])]},InstructionPcode{address:0x110,length:4,operations:vec![op(OpCode::IntAdd,Some(n("register",2)),vec![n("register",1)])]}];let r=SsaAnalyzer.analyze(&cfg,&pc);assert_eq!(r.blocks[1].operations[0].uses[0].version,r.blocks[0].operations[0].definition.as_ref().unwrap().version);assert_eq!(r.phi_count,0);}
}
