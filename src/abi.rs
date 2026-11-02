//! Scalar calling-convention argument locations for common 64-bit ABIs.
//!
//! Aggregate classification is intentionally conservative. Correct System V
//! eightbyte and AAPCS64 HFA/HVA handling requires recovered type layouts.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Abi { SystemVx86_64, WindowsX64, Aapcs64 }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AbiValueClass { Integer, FloatingPoint, Aggregate }
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AbiLocation {
    Register { name: &'static str, size: u32 },
    Stack { offset_from_entry_sp: u32, size: u32, alignment: u32 },
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AbiProfile {
    pub abi: Abi, pub stack_alignment: u32, pub entry_stack_bias: u32, pub shadow_space: u32,
    pub integer_return_registers: &'static [&'static str], pub floating_return_registers: &'static [&'static str],
}
impl AbiProfile {
    pub const fn for_abi(abi: Abi) -> Self {
        match abi {
            Abi::SystemVx86_64 => Self { abi, stack_alignment:16, entry_stack_bias:8, shadow_space:0, integer_return_registers:&["rax","rdx"], floating_return_registers:&["xmm0","xmm1"] },
            Abi::WindowsX64 => Self { abi, stack_alignment:16, entry_stack_bias:8, shadow_space:32, integer_return_registers:&["rax"], floating_return_registers:&["xmm0"] },
            Abi::Aapcs64 => Self { abi, stack_alignment:16, entry_stack_bias:0, shadow_space:0, integer_return_registers:&["x0","x1"], floating_return_registers:&["v0","v1"] },
        }
    }
    pub fn allocator(&self) -> AbiArgumentAllocator {
        AbiArgumentAllocator { profile:self.clone(), argument_index:0, integer_index:0, floating_index:0, stack_cursor:self.entry_stack_bias+self.shadow_space }
    }
}
#[derive(Clone, Debug)]
pub struct AbiArgumentAllocator { profile:AbiProfile, argument_index:usize, integer_index:usize, floating_index:usize, stack_cursor:u32 }
impl AbiArgumentAllocator {
    pub fn next(&mut self, class:AbiValueClass, size:u32) -> AbiLocation {
        let size=size.max(1);
        let loc=match self.profile.abi { Abi::SystemVx86_64=>self.system_v(size,class), Abi::WindowsX64=>self.windows_x64(size,class), Abi::Aapcs64=>self.aapcs64(size,class) };
        self.argument_index+=1; loc
    }
    fn system_v(&mut self,size:u32,class:AbiValueClass)->AbiLocation {
        const GP:&[&str]=&["rdi","rsi","rdx","rcx","r8","r9"];
        const FP:&[&str]=&["xmm0","xmm1","xmm2","xmm3","xmm4","xmm5","xmm6","xmm7"];
        let r=match class { AbiValueClass::Integer if size<=8=>take_register(GP,&mut self.integer_index), AbiValueClass::FloatingPoint if size<=16=>take_register(FP,&mut self.floating_index), _=>None };
        r.map_or_else(||self.stack(size,8),|name|AbiLocation::Register{name,size})
    }
    fn windows_x64(&mut self,size:u32,class:AbiValueClass)->AbiLocation {
        const GP:&[&str]=&["rcx","rdx","r8","r9"]; const FP:&[&str]=&["xmm0","xmm1","xmm2","xmm3"];
        let slot=self.argument_index;
        let r=if slot<4 && size<=8 { match class { AbiValueClass::Integer=>Some(GP[slot]), AbiValueClass::FloatingPoint=>Some(FP[slot]), AbiValueClass::Aggregate=>None } } else {None};
        r.map_or_else(||self.stack(size,8),|name|AbiLocation::Register{name,size})
    }
    fn aapcs64(&mut self,size:u32,class:AbiValueClass)->AbiLocation {
        const GP:&[&str]=&["x0","x1","x2","x3","x4","x5","x6","x7"];
        const FP:&[&str]=&["v0","v1","v2","v3","v4","v5","v6","v7"];
        let r=match class { AbiValueClass::Integer if size<=8=>take_register(GP,&mut self.integer_index), AbiValueClass::FloatingPoint if size<=16=>take_register(FP,&mut self.floating_index), _=>None };
        r.map_or_else(||self.stack(size,8),|name|AbiLocation::Register{name,size})
    }
    fn stack(&mut self,size:u32,alignment:u32)->AbiLocation {
        let alignment=alignment.max(8).next_power_of_two().min(16); self.stack_cursor=align_up(self.stack_cursor,alignment);
        let offset=self.stack_cursor; self.stack_cursor=self.stack_cursor.saturating_add(align_up(size,8));
        AbiLocation::Stack{offset_from_entry_sp:offset,size,alignment}
    }
    pub fn arguments_allocated(&self)->usize { self.argument_index }
}
fn take_register(regs:&[&'static str],index:&mut usize)->Option<&'static str> { let r=regs.get(*index).copied(); if r.is_some(){*index+=1;} r }
fn align_up(v:u32,a:u32)->u32 { v.saturating_add(a-1)&!(a-1) }
#[cfg(test)] mod tests {
 use super::*;
 #[test] fn system_v_gp_registers_then_stack(){let mut a=AbiProfile::for_abi(Abi::SystemVx86_64).allocator();for n in ["rdi","rsi","rdx","rcx","r8","r9"]{assert_eq!(a.next(AbiValueClass::Integer,8),AbiLocation::Register{name:n,size:8});}assert_eq!(a.next(AbiValueClass::Integer,8),AbiLocation::Stack{offset_from_entry_sp:8,size:8,alignment:8});}
 #[test] fn windows_positional_slots_and_shadow_space(){let mut a=AbiProfile::for_abi(Abi::WindowsX64).allocator();assert_eq!(a.next(AbiValueClass::Integer,8),AbiLocation::Register{name:"rcx",size:8});assert_eq!(a.next(AbiValueClass::FloatingPoint,8),AbiLocation::Register{name:"xmm1",size:8});for _ in 0..2{a.next(AbiValueClass::Integer,8);}assert_eq!(a.next(AbiValueClass::Integer,8),AbiLocation::Stack{offset_from_entry_sp:40,size:8,alignment:8});}
 #[test] fn aapcs64_register_banks_are_independent(){let mut a=AbiProfile::for_abi(Abi::Aapcs64).allocator();assert_eq!(a.next(AbiValueClass::FloatingPoint,8),AbiLocation::Register{name:"v0",size:8});assert_eq!(a.next(AbiValueClass::Integer,8),AbiLocation::Register{name:"x0",size:8});for _ in 0..7{a.next(AbiValueClass::Integer,8);}assert_eq!(a.next(AbiValueClass::Integer,8),AbiLocation::Stack{offset_from_entry_sp:0,size:8,alignment:8});}
 #[test] fn aggregates_are_not_guessed_into_scalar_registers(){let mut a=AbiProfile::for_abi(Abi::SystemVx86_64).allocator();assert!(matches!(a.next(AbiValueClass::Aggregate,16),AbiLocation::Stack{..}));}
}
