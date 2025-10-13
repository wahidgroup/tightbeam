#[macro_export]
macro_rules! doc {
    // Store a named doc block
    (
        name: $name:ident,
        $($doc_attr:meta)*
        $item:item
    ) => {
        // Store the documentation in a const for later retrieval
        #[doc(hidden)]
        const $name: &'static str = concat!(
            $(stringify!($doc_attr), "\n",)*
            stringify!($item)
        );

        // Also emit the original item with docs
        $(#[$doc_attr])*
        $item
    };

    // Retrieve and emit a stored doc block
    ($name:ident) => {
        #[doc = $name]
        ///
    };
}
