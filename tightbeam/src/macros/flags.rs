#[macro_export]
macro_rules! flags {
	 ($flagset_type:ty: $($flag:expr),* $(,)?) => {{
		let mut flagset = <$flagset_type>::default();
		$(
		  flagset.set($flag);
		)*
		flagset
	 }};
}

#[macro_export]
macro_rules! flagset {
	 ($name:ident: $first:ty $(, $rest:ty)* $(,)?) => {
		pub struct $name {
		  flags: $crate::flags::Flags<{ tightbeam::flagset!(@count $first $(, $rest)*) }>,
		}

		impl Default for $name {
			fn default() -> Self {
				Self {
					flags: $crate::flags::Flags::default(),
				}
			}
		}

		impl From<$name> for $crate::flags::Flags<{ tightbeam::flagset!(@count $first $(, $rest)*) }> {
		  fn from(flagset: $name) -> $crate::flags::Flags<{ tightbeam::flagset!(@count $first $(, $rest)*) }> {
			 flagset.flags
		  }
		}

		impl From<Vec<u8>> for $name {
		  fn from(bytes: Vec<u8>) -> Self {
			 Self {
				flags: $crate::flags::Flags::from(bytes.as_slice()),
			 }
		  }
		}

		impl From<&[u8]> for $name {
		  fn from(bytes: &[u8]) -> Self {
			 Self {
				flags: $crate::flags::Flags::from(bytes),
			 }
		  }
		}

		impl From<Option<Vec<u8>>> for $name {
		  fn from(bytes: Option<Vec<u8>>) -> Self {
			 match bytes {
				Some(bytes) => Self::from(bytes),
				None => Self::default(),
			 }
		  }
		}

		impl $name {
		  fn get_pos(type_name: &str) -> usize {
			 tightbeam::flagset!(@position_lookup type_name, 0, $first $(, $rest)*)
		  }
		}

		impl<T> $crate::flags::FlagSet<T> for $name
		where
		  T: Into<u8> + PartialEq<u8> + Default + 'static,
		{
		  fn set(&mut self, flag: T)
		  where
			 T: Into<u8> + 'static,
		  {
			 let type_name = std::any::type_name::<T>();
			 let type_name = core::any::type_name::<T>();
			 let pos = Self::get_pos(type_name);
			 self.flags.set_at(pos, flag.into());
		  }

		  fn unset(&mut self) {
			 let type_name = std::any::type_name::<T>();
			 let type_name = core::any::type_name::<T>();
			 let pos = Self::get_pos(type_name);
			 self.flags.set_at(pos, T::default().into());
		  }

		  fn contains(&self, flag: T) -> bool
		  where
			 T: Into<u8> + PartialEq<u8> + Default + 'static,
		  {
			 let type_name = std::any::type_name::<T>();
			 let type_name = core::any::type_name::<T>();
			 let pos = Self::get_pos(type_name);
			 let stored_value = self.flags.get_at(pos);
			 let flag_value = flag.into();

			 // If the flag matches what's stored, return true
			 // If nothing is stored (0), compare against the default value
			 if stored_value == flag_value {
				true
			 } else if stored_value == 0 {
				flag_value == T::default().into()
			 } else {
				false
			 }
		  }
		}

		impl From<$name> for Vec<u8> {
		  fn from(flagset: $name) -> Vec<u8> {
			 Vec::from(flagset.flags)
		  }
		}
	 };

	 (@count $first:ty) => { 1 };
	 (@count $first:ty, $($rest:ty),*) => { 1 + tightbeam::flagset!(@count $($rest),*) };

	 (@impl_methods $pos:ident = $pos_val:expr, $first:ty) => {
		tightbeam::flagset!(@method_for_type $pos_val, $first);
	 };

	 (@impl_methods $pos:ident = $pos_val:expr, $first:ty, $($rest:ty),*) => {
		tightbeam::flagset!(@method_for_type $pos_val, $first);
		tightbeam::flagset!(@impl_methods $pos = $pos_val + 1, $($rest),*);
	 };

	 (@position_lookup $type_name:expr, $pos:expr, $ty:ty) => {
		if $type_name.ends_with(stringify!($ty)) { $pos } else { usize::MAX }
	 };

	 (@position_lookup $type_name:expr, $pos:expr, $ty:ty, $($rest:ty),*) => {
		if $type_name.ends_with(stringify!($ty)) {
		  $pos
		} else {
		  tightbeam::flagset!(@position_lookup $type_name, $pos + 1, $($rest),*)
		}
	 };
}
