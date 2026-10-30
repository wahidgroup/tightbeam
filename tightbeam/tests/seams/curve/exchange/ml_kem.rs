//! ML-KEM-768 (FIPS 203) as an outside crate brings it, through `ml-kem`.
//!
//! [`MlKem768`] is a KEM. Its reply is a ciphertext, which travels in the CMS
//! Finished as a `KemCiphertext`, and its shares collapse into no static key.
//! Each of its operations runs one vector of the NIST ACVP for FIPS 203, from
//! the `internalProjection` files of ACVP-Server at commit `65370b8`:
//!
//! - key generation: `ML-KEM-keyGen-FIPS203`, ML-KEM-768, tcId 26,
//! - encapsulation: `ML-KEM-encapDecap-FIPS203`, ML-KEM-768, tcId 26, and
//! - decapsulation: `ML-KEM-encapDecap-FIPS203`, ML-KEM-768, tgId 5 and tcId 88.

use core::convert::Infallible;
use std::error::Error;

use ml_kem::array::typenum::Unsigned;
use ml_kem::kem::{Decapsulate, DecapsulationKey, Encapsulate, EncapsulationKey};
use ml_kem::{Ciphertext, Encoded, EncodedSizeUser, KemCore, MlKem768Params};
use tightbeam::cms::enveloped_data::OriginatorPublicKey;
use tightbeam::crypto::exchange::{KemCiphertext, KeyExchange, KeyExchangeError, KeyShare, ReplyAttribute, ReplyKind};
use tightbeam::crypto::profiles::SecurityStrength;
use tightbeam::crypto::secret::SecretSlice;
use tightbeam::der::asn1::{ObjectIdentifier, OctetString};
use tightbeam::der::oid::AssociatedOid;
use tightbeam::der::Any;
use tightbeam::oids::CURVE_X25519;
use tightbeam::random::{CryptoRngCore, OsRng};
use tightbeam::spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoRef};
use tightbeam::testing::unhex;
use tightbeam::zeroize::Zeroize;

use super::{cms_opens, hpke_opens, p384_identity, OnP384, PublishedDraw, CONTENT};

/// `id-alg-ml-kem-768` (NIST CSOR).
const ID_ML_KEM_768: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.4.2");

/// Key generation: the seed `d`.
const ACVP_KEYGEN_D: &str = "e34a701c4c87582f42264ee422d3c684d97611f2523efe0c998af05056d693dc";

/// Key generation: the seed `z`.
const ACVP_KEYGEN_Z: &str = "a85768f3486bd32a01bf9a8f21ea938e648eae4e5448c34c3eb88820b159eedd";

/// Key generation: the encapsulation key of `d` and `z`.
const ACVP_KEYGEN_EK: &str = "6d14a071f7cc452558d5e71a7b087062ecb1386844588246126402b1fa1637733cd5f60cc84bcb646a7892\
	614d7c51b1c7f1a2799132f13427dc482158da254470a59e00a4e49686fdc077559367270c2153f11007592c9c4310cf8a12c6a8713b\
	d6bb51f3124f989ba0d54073cc242e0968780b875a869efb851586b9a868a384b9e6821b201b932c455369a739ec22569c977c212b38\
	1871813656af5b567ef893b584624c863a259000f17b254b98b185097c50ebb68b244342e05d4de520125b8e1033b1436093ace7ce8e\
	71b458d525673363045a3b3eea9455428a398705a42327adb3774b7057f42b017ec0739a983f19e8214d09195fa24d2d571db73c19a6\
	f8460e50830d415f627b88e94a7b153791a0c0c7e9484c74d53c714889f0e321b6660a532a5bc0e557fbca35e29bc611200ed3c63307\
	7a4d873c5cc67006b753bf6d6b7af6ca402ab618236c0affbc801f8222fbc36ce0984e2b18c944bbcbef03b1e1361c1f44b0d734afb1\
	566cff8744da8b9943d6b45a3c09030702ca201ffe20cb7ec5b0d4149ee2c28e8b23374f471b57150d0ec9336261a2d5cb84a3acacc4\
	289473a4c0abc617c9abc178734434c82e1685588a5c2ea2678f6b3c2228733130c466e5b86ef491153e48662247b875d201020b566b\
	81b64d839ab4633baa8ace202baab4496297f9807adbbb1e332c6f8022b2a18cfdd4a82530b6d3f007c3353898d966cc2c21cb4244bd\
	00443f209870acc42bc33068c724ec17223619c1093cca6aeb29500664d1225036b4b81091906969481f1c723c140b9d6c168f5b64be\
	a69c5fd6385df7364b8723bcc85e038c7e464a900d68a2127818994217aec8bdb39a970a9963de93688e2ac82abcc22fb9277ba22009\
	e878381a38163901c7d4c85019538d35caae9c41af8c929ee20bb08ca619e72c2f2262c1c9938572551ac02dc9268fbcc35d79011c3c\
	090ad40a4f111c9be55c427eb796c1932d8673579af1b4c638b0944489012a2559a3b02481b01ac30ba8960f80c0c2b3947d36a12c08\
	0498bee448716c973416c8242804a3da099ee137b0ba90fe4a5c6a89200276a0cfb643ec2c56a2d708d7b4373e44c1502a763a600586\
	e6cda6273897d44448287dc2e602dc39200bf6166236559fd12a60892aeb153dd651bb469910b4b34669f91da8654d1eb72eb6e02800\
	b3b0a7d0a48c836854d3a83e65569cb7230bb44f3f143a6dec5f2c39ab90f274f2088bd3d6a6fca0070273bedc84777fb52e3c558b0a\
	e06183d5a48d452f68e15207f861627aca14279630f82ec3a0ca078633b600afa79743a600215be5637458ce2ce8aff5a08eb5017b2c\
	766577479f8dc6bf9f5cc75089932161b96cea406620aedb630407f7687ebbb4814c7981637a48a90de68031e062a7af7612b4f5c7a6\
	da86bd136529e64295a5613ea73bd3d4448cb81f243135c0a660beb9c17e651def469a7d90a15d3481090bcbf227012328941fa46f39\
	c5006ad93d458aa6add655862b418c3094f551460df2153a5810a7da74f0614c2588be49dc6f5e88154642bd1d376256332643350715\
	6a57c57694bdd26e7a246feb723aed67b04887c8e476b48cab59e5362f26a9ef50c2bc80ba146226216fe62968a60d04e8c170d741c7\
	a2b0e1abdac968";

/// Encapsulation: the encapsulation key.
const ACVP_ENCAP_EK: &str = "89d2cb65f94dcbfc890efc7d0e5a7a38344d1641a3d0b024d50797a5f23c3a18b3101a1269069f43a842ba\
	cc098a8821271c673db1beb33034e4d7774d16635c7c2c3c2763453538bc1632e1851591a51642974e5928abb8e55fe55612f9b141af\
	f015545394b2092e590970ec29a7b7e7aa1fb4493bf7cb731906c2a5cb49e6614859064e19b8fa26af51c44b5e7535bfdac072b646d3\
	ea490d277f0d97ced47395fed91e8f2bce0e3ca122c2025f74067ab928a822b35653a74f06757629afb1a1caf237100ea935e793c8f5\
	8a71b3d6ae2c8658b10150d4a38f572a0d49d28ae89451d338326fdb3b4350036c1081117740edb86b12081c5c1223dbb5660d5b3cb3\
	787d481849304c68be875466f14ee5495c2bd795ae412d09002d65b8719b90cba3603ac4958ea03cc138c86f7851593125334701b677\
	f82f4952a4c93b5b4c134bb42a857fd15c650864a6aa94eb691c0b691be4684c1f5b7490467fc01b1d1fda4dda35c4ecc231bc73a6fe\
	f42c99d34eb82a4d014987b3e386910c62679a118f3c5bd9f467e4162042424357db92ef484a4a1798c1257e870a30cb20aaa0335d83\
	314fe0aa7e63a862648041a72a6321523220b1ace9bb701b21ac1253cb812c15575a9085eabeade73a4ae76e6a7b158a20586d78a5ac\
	620a5c9abcc9c043350a73656b0abe822da5e0ba76045fad75401d7a3b703791b7e99261710f86b72421d240a347638377205a152c79\
	4130a4e047742b888303bddc309116764de7424cebea6db65348ac537e01a9cc56ea667d5aa87ac9aaa4317d262c10143050b8d07a72\
	8ca633c13e468abcead372c77b8ecf3b986b98c1e55860b2b4216766ad874c35ed7205068739230220b5a2317d102c598356f168acbe\
	80608de4c9a710b8dd07078cd7c671058af1b0b8304a314f7b29be78a933c7b9294424954a1bf8bc745de86198659e0e1225a9107260\
	74969c39a97c19240601a46e013dcdcb677a8cbd2c95a40629c256f24a328951df57502ab30772cc7e5b850027c8551781ce4985bdac\
	f6b865c104e8a4bc65c41694d456b7169e45ab3d7acabeafe23ad6a7b94d1979a2f4c1cae7cd77d681d290b5d8e451bfdcccf5310b9d\
	12a88ec29b10255d5e17a192670aa9731c5ca67ec784c502781be8527d6fc003c6701b3632284b40307a527c7620377feb0b73f722c9\
	e3cd4dec64876b93ab5b7cfc4a657f852b659282864384f442b22e8a21109387b8b47585fc680d0ba45c7a8b1d7274bda57845d100d0\
	f42a3b74628773351fd7ac305b2497639be90b3f4f71a6aa3561eecc6a691bb5cb3914d8634ca1e1af543c049a8c6e868c51f0423bd2\
	d5ae09b79e57c27f3fe3ae2b26a441babfc6718ce8c05b4fe793b910b8fbcbbe7f1013242b40e0514d0bdc5c88bac594c794ce5122fb\
	f34896819147b928381587963b0b90034aa07a10be176e01c80ad6a4b71b10af4241400a2a4cbbc05961a15ec1474ed51a3cc6d35800\
	679a462809caa3ab4f7094cd6610b4a700cba939e7eac93e38c99755908727619ed76a34e53c4fa25bfc97008206697dd145e5b9188e\
	5b014e941681e15fe3e132b8a3903474148ba28b987111c9bcb3989bbbc671c581b44a492845f288e62196e471fed3c39c1bbddb0837\
	d0d4706b0922c4";

/// Encapsulation: the message `m` it draws.
const ACVP_ENCAP_M: &str = "2ce74ad291133518fe60c7df5d251b9d82add48462ff505c6e547e949e6b6bf7";

/// Encapsulation: the ciphertext.
const ACVP_ENCAP_C: &str = "56b42d593aab8e8773bd92d76eabddf3b1546f8326f57a7b773764b6c0dd30470f68dff82e0dca92509274ec\
	fe83a954735fde6e14676daaa3680c30d524f4efa79ed6a1f9ed7e1c00560e8683538c3105ab931be0d2b249b38cb9b13af5ceaf7887\
	a59dba16688a7f28de0b14d19f391eb41832a56479416ccf94e997390ed7878eeaff49328a70e0ab5fce6c63c09b35f4e45994de615b\
	88bb722f70e87d2bbd72ae71e1ee9008e459d8e743039a8ddeb874fce5301a2f8c0ee8c2fee7a4ee68b5ed6a6d9ab74f98bb3ba0fe89\
	e82bd5a525c5e8790f818ccc605877d46c8bdb5c337b025bb840ff471896e43bfa99d73dbe31805c27a43e57f0618b3ae522a4644e0d\
	4e4c1c548489431be558f3bfc50e16617e110dd7af9a6fd83e3fbb68c304d15f6cb700d61d7aa915a6751ea3ba80223e654132a20999\
	a43bf408592730b9a9499636c09fa729f9cb1f9d3442f47357a2b9cf15d3103b9bf396c23088f118ede346b5c03891cfa5d517cef847\
	1322e7e31087c4b036abad784bff72a9b11fa198facbcb91f067feaf76fcfe5327c1070b3da6988400756760d2d1f060298f1683d51e\
	3616e98c51c9c03aa42f2e633651a47ad3cc2ab4a852ae0c4b04b4e1c3dd944445a2b12b4f42a6435105c04122fc3587afe409a00b30\
	8d63c5dd8163654504eedbb7b5329577c35fbeb3f463872cac28142b3c12a740ec6ea7ce9ad78c6fc8fe1b4df5fc55c1667f31f2312d\
	a07799dc870a478608549fedafe021f1cf2984180364e90ad98d845652aa3cdd7a8eb09f5e51423fab42a7b7bb4d514864be8d71297e\
	9c3b17a993f0ae62e8ef52637bd1b885bd9b6ab727854d703d8dc478f96cb81fce4c60383ac01fcf0f971d4c8f352b7a82e218652f2c\
	106ca92ae686bacfcef5d327347a97a9b375d67341552bc2c538778e0f9801823ccdfcd1eaaded55b18c9757e3f212b2889d3857db51\
	f981d16185fd0f900853a75005e3020a8b95b7d8f2f2631c70d78a957c7a62e1b3719070acd1fd480c25b83847da027b6ebbc2eec2df\
	22c87f9b46d5d7baf156b53cee929572b92c4784c4e829f3446a1ffe47f99decd0436029ddebd3ed8e87e5e73d123dbe8a4ddacf2abd\
	e87f33ae2b621c0ec5d5cad1259deec2aeff6088f04f27a20338b5762543e5100899a4cbfb7b3ca456b3a19b83a4c432230c23e1c7f1\
	07c4cb112152f1c0f30da0bb33f4f11f47eea43872bafa84ae22256d708e0604dade4b2a4dde8cccf11930e13553934ae3ece52f3d7c\
	cc00287377879fe6b8ece7ef79423507c9da339559c20de1c51955999bae47401dc3cdfaa1b256d09c7db9fc8698bfcefa7302d56fbc\
	de1fbaaa1c653454e6fd3d84e4f79a931c681cbb6cb462b10dae112bdfb7f65c7fdf6e5fc594ec3a474a94bd97e6ec81f71c230bf70c\
	a0f13ce3dffbd9ff9804efd8f37a4d3629b43a8f55544ebc5ac0abd9a33d79699068346a0f1a3a96e115a5d80be165b562d082984d5a\
	acc3a2301981a6418f8ba7d7b0d7ca5875c6";

/// Encapsulation: the shared key.
const ACVP_ENCAP_K: &str = "2696d28e9c61c2a01ce9b1608dcb9d292785a0cd58efb7fe13b1de95f0db55b3";

/// Decapsulation: the decapsulation key of the group.
const ACVP_DECAP_DK: &str = "1e4ac87b1a692a529fdbbab93374c57d110b10f2b1ddebac0d196b7ba631b8e9293028a8f379888c422dc8\
	d32bbf226010c2c1ec73189080456b0564b258b0f23131bc79c8e8c11cef3938b243c5ce9c0edd37c8f9d29877dbbb615b9b5ac3c948\
	487e467196a9143efbc7cedb64b45d4acda2666cbc2804f2c8662e128f6a9969ec15bc0b9351f6f96346aa7abc743a14fa030e37a2e7\
	597bddfc5a22f9cedaf8614832527210b26f024c7f6c0dcf551e97a4858764c321d1834ad51d75bb246d277237b7bd41dc4362d063f4\
	298292272d01011780b79856b296c4e946658b79603197c9b2a99ec66acb06ce2f69b5a5a61e9bd06ad443ceb0c74ed65345a903b614\
	e81368aac2b3d2a79ca8ccaa1c3b88fb82a36632860b3f7950833fd0212ec96ede4ab6f5a0bda3ec6060a658f9457f6cc87c6b620c1a\
	1451987486e496612a101d0e9c20577c571edb5282608bf4e1ac926c0db1c82a504a799d89885ca6252bd5b1c183af701392a407c05b\
	848c2a3016c40613f02a449b3c7926da067a533116506840097510460bbfd36073dcb0bfa009b36a9123eaa68f835f74a01b00d20978\
	35964df521ce9210789c30b7f06e5844b444c53322396e4799baf6a88af7315860d0192d48c2c0da6b5ba64325543acdf5900e8bc477\
	ab05820072d463affed097e062bd78c99d12b385131a241b708865b4190af69ea0a64db71448a60829369c7555198e438c9abc310bc7\
	0101913bb12faa5beef975841617c847cd6b336f877987753822020b92c4cc97055c9b1e0b128bf11f505005b6ab0e627795a20609ef\
	a991e598b80f37b1c6a1c3a1e9aee7028f77570ab2139128a00108c50eb305cdb8f9a603a6b078413f6f9b14c6d82b5199ce59d88790\
	2a281a027b717495fe12672a127bbf9b256c43720d7c160b281c12757da135b1933352be4ab67e40248afc318e2370c3b8208e695bdf\
	337459b9acbfe5b487f76e9b4b4001d6cf90ca8c699a174d42972dc733f33389fdf59a1daba81d834955027334185ad02c76cf294846\
	ca9294ba0ed66741ddec791cab34196ac5657c5a78321b56c33306b5102397a5c09c3508f76b48282459f81d0c72a43f737bc2f12f45\
	422628b67db51ac1424276a6c08c3f7615665bbb8e928148a270f991bcf365a90f87c30687b68809c91f231813b866bea82e30374d80\
	aa0c02973437498a53b14bf6b6ca1ed76ab8a20d54a083f4a26b7c038d81967640c20bf4431e71dacce8577b21240e494c31f2d877da\
	f4924fd39d82d6167fbcc1f9c5a259f843e30987ccc4bce7493a2404b5e44387f707425781b743fb555685584e2557cc038b1a9b3f40\
	43121f5472eb2b96e5941fec011ceea50791636c6abc26c1377ee3b5146fc7c85cb335b1e795eec2033ee44b9aa90685245ef7b4436c\
	000e66bc8bcbf1cdb803ac1421b1fdb266d5291c8310373a8a3ce9562ab197953871ab99f382cc5aa9c0f273d1dca55d2712853871e1\
	a83cb3b85450f76d3f3c42bab5505f7212fdb6b8b7f6029972a8f3751e4c94c1108b02d6ac79f8d938f05a1b2c229b14b42b31b01a36\
	4017e59578c6b033833774cb9b570f9086b722903b375446b495d8a29bf80751877a80fb724a0210c3e1692f397c2f1ddc2e6ba17af8\
	1b92acfabef5f7573cb493d184027b718238c89a3549b8905b28a83362867c082d3019d3ca70700731ceb73e8472c1a3a093361c5fea\
	6a7d40955d07a41b64e50081a361b604cc518447c8e25765ab7d68b243275207af8ca6564a4cb1e94199dba1878c59bec809ab48b2f2\
	11badc6a1998d9c7227c1303f469d46a9c7e5303f98aba67569ae8227c16ba1fb3244466a25e7f823671810cc26206feb29c7e2a1a91\
	959eeb03a98252a4f7412674eb9a4b277e1f2595fca64033b41b40330812e9735b7c607501cd8183a22afc3392553744f33c4d202526\
	945c6d78a60e201a16987a6fa59d94464b56506556784824a07058f57320e76c825b9347f2936f4a0e5cdaa18cf8833945ae312a36b5\
	f5a3810aac82381fdae4cb9c6831d8eb8abab850416443d739086b1c326fc2a3975704e396a59680c3b5f360f5480d2b62169cd94ca7\
	1b37bc5878ba2985e068ba050b2ce50726d4b4451b77aaa8676eae094982210192197b1e92a27f59868b78867887b9a70c32af84630a\
	a908814379e6519150ba16439b5e2b0603d06aa6674557f5b0983e5cb6a97596069b01bb3128c416680657204fd07640392e16b19f33\
	7a99a304844e1aa474e9c799062971f672268960f5a82f950070bbe9c2a71950a3785bdf0b8440255ed63928d257845168b1eccc4191\
	325aa76645719b28ebd89302dc6723c786df5217b243099ca78238e57e64692f206b177abc259660395cd7860fb35a16f6b2fe6548c8\
	5ab66330c517fa74cdf3cb49d26b1181901af775a1e180813b6a24c456829b5c38104ece43c76a437a6a33b6fc6c5e65c8a89466c142\
	5485b29b9e1854368afca353e143d0a90a6c6c9e7fdb62a606856b5614f12b64b796020c3534c3605cfdc73b86714f411850228a28b8\
	f4b49e663416c84f7e381f6af1071343bf9d39b45439240cc03897295fea080b14bb2d8119a880e164495c61bebc7139c11857c85e17\
	50338d6343913706a507c9566464cd2837cf914d1a3c35e89b235c6ab7ed078bed234757c02ef6993d4a273cb8150528da4d76708177\
	e9425546c83e147039766603b30da6268f4598a53194240a2832a3d67533b5056f9aaac61b4b17b9a2693aa0d58891e6cc56cdd77241\
	0900c405af20b903797c64876915c37b8487a1449ce924cd345c29a36e08238f7a157cc7e516ab5ba73c8063f726bb5a0a0319e57127\
	438c7fc601c99ccaae4c1a83726fdcb5045ed1a82a985ea995396d77272c66ce493289f6110910f37c2741ce47026a6f8261999c6482\
	572b1693912ef12eebea7acf9234fb409f2a6090e6b0bfd895469d0b2a921bb723f87a33ea5465ab90f514b67698c0768b6ca498b022\
	c512fa0875f054aa2265867e31c0e522651e024a07d60dd9f633166921f4126bc2b6aa01cc15a09b85bff8218c5aae95bc1ffb26ae5a\
	137670f04910ca9d7241b6660c394c5455917746a26682fb71a432ea9530e839bdeb07433004f45a0ddaa0b24e3a566a540815f281e3\
	fc259ac6cbc0acb8d62268b603bc676ab415c474bb94873e4487ae31a4e3845c79901550890ee8784eef904fee62ba8c5f952c684130\
	52e0a7e3388bb8ff0ad602ae3ea14d9df6dd5e4cc6a381a41da5c137ecc49df587e178eaf47702ec623780691a3233f69f12bd9c9b96\
	37c51378ad71a831055277254cc63c5ad4cb76b4ab82e5fca135e8d26a6b3a89fa5b6f";

/// Decapsulation: the ciphertext.
const ACVP_DECAP_C: &str = "a5c81c76c24305e1ce5d8135d41523682e9ee6d7b40ad41df1f37c9b17dce78076019a6b0b7c95c9be7af295\
	07b2d5a6987c8ee3259190855243e6e56f5620608c52d96fab103a8700fba1a87dca6078118a0871762c9534c0c0c3978c91c3a01f0f\
	608dcf757815438fe8957c8a859183b1b6721a0865bebc799d4e5c0e7bd3eae4858e6ab6a2e7658ed80d4ed158b036b93fa03afa6ae3\
	136cf3d693c911bcc75905e5b0cb2865b9e9884522a77777613e53111d5a1c7d3dab734ceb03657ae0c89763e99471054776bae7d51b\
	0e73a5bb35aec30ff6bc93684916fef1162586452f426653e2ca844d5744307ff9aeb287a6447783b21a0e939c81421d631f5dcb452e\
	51ed34e3dad1cf504e0a3b0f4711a8dc6499d1691d109569336ce1558a4c0a464e2087ea8f9e3b18f747ef61f4576aeb42b17cadb7f0\
	fd84da8e3a6f471d95edfa65be9e6c9f6ae756a22a4f1a5c543c26ba7bad88e16d5f5b7e12e2d4ca34b3a64d17f87ccfc4ff8c5e4f53\
	752a077c68721e8cc817f9ff24876170ff2af89fa95855a5b1de347c07fddbcfe7264aa5ed6401491561d831538f852b0ed7b9e8ebaf\
	fc060284f22d2baee56fa9f6d01432a115a2d6a64c38ae0a50ba362fb57b53e3e855b83ce8c42274045599f65fa6a8921d85f94ed230\
	b516712db6fd2ff28b3a3371d9be058ae75c2fa591b7ec3c3daa1f7642bc26c324c08090607e6662154db37cf747967a1f9fc29089f5\
	70ebe60eeef89fd24481028c85aef1dc3b09f22cd3691bbbb821c7a8a0f35ad12be1dd199b977048f3d48c16bb2ca94cecb8928770d5\
	bb329a0327e0b286faa1c65281031a31c84f2edc9c04d475ed4e128e51efa97d0148cba6c95f674c589f301c265bed708e9ad8da3c5c\
	ecbdeeed35ef1e253132ba89920d786b88230b013bcf2dc92d6b157afa8da8592cd0743d4982be60d7c2d5c472ab9fa7f4cc3d12b0eb\
	af0abe555c75805426844dd9428643f84406a1b8d6faedfd8ae6e73a72772a2159acabd972aeb6f7de091ac5fdd7f49a3dc6641cdf62\
	446b4b04a31f73b80a62f80a404a8cb18ce3e65480ef7b52bf0091117e5d08eae1b0aabb72e6dffff76f6e44bbd7ea570d6604bc2e74\
	318bafa315a38861aa1b21afb2a53f2614f1d640075984ae62e2fca1d1b4db369f15705ce7d4df8ae98264501051c0def21d645d4962\
	5af02ca428d9f0c2cd9fbaeeab97e8e9151662b6992b4c99ab1b925d08920363373f76d3fdf0828caa69c8b1bdc6f521df641cf1c8a4\
	e7ef0c23289a4e2cf18acebbe4c1e68369bd5235120142ecdd1a73811e2e533a647d7aee16daa03b683639dcf1e1f1e71cfaed48f69a\
	ec3e831733da19cebec1ddbf71cbae0800f2f6d64a096ec495d62f4344f7aa5621b322353a795aa099ea3a070272d053d4653a20cf21\
	0eaaf12cae6023d8e5118df04b384a44d1edb91c44989ef7ee57f2bf81a24bdc76807da967ee6525410c5c485067efc3d39a9ad42cc7\
	53baa59a1fd28af35c00d18a406a28fc79ba";

/// Decapsulation: the shared key.
const ACVP_DECAP_K: &str = "dc5b8888bc1eba5c1969c21164ea43e22e7ac0cd012a2f26cb8c487e69ef7ce4";

/// The encapsulation key of ML-KEM-768.
type MlKemEncapsulationKey = EncapsulationKey<MlKem768Params>;

/// The decapsulation key of ML-KEM-768, which wipes where it drops.
type MlKemDecapsulationKey = DecapsulationKey<MlKem768Params>;

/// ML-KEM-768 (FIPS 203) in the exchange role, as an outside crate writes it.
#[derive(Debug, Default, Clone, Copy)]
pub(super) struct MlKem768;

impl AssociatedOid for MlKem768 {
	const OID: ObjectIdentifier = ID_ML_KEM_768;
}

/// The initiator's share of [`MlKem768`]: an encapsulation key.
pub(super) struct EncapsulationShare(MlKemEncapsulationKey);

/// The responder's share of [`MlKem768`]: a ciphertext.
pub(super) struct CiphertextShare(Ciphertext<ml_kem::MlKem768>);

/// The CMS forms are the provided ones: the opening names the key by its
/// identifier, with no parameters.
impl KeyShare<MlKem768> for EncapsulationShare {
	/// The key passes the modulus check of FIPS 203 §7.2: it encodes to the
	/// octets it decodes from, so every coefficient is below the modulus.
	fn from_octets(octets: &[u8]) -> Result<Self, KeyExchangeError> {
		let expected = <MlKemEncapsulationKey as EncodedSizeUser>::EncodedSize::USIZE;
		let encoded = Encoded::<MlKemEncapsulationKey>::try_from(octets);
		let encoded = encoded.map_err(|_| KeyExchangeError::Width { expected, actual: octets.len() })?;

		let key = MlKemEncapsulationKey::from_bytes(&encoded);
		if key.as_bytes() != encoded {
			return Err(KeyExchangeError::Malformed);
		}

		Ok(Self(key))
	}

	fn to_octets(&self) -> Vec<u8> {
		self.0.as_bytes().to_vec()
	}

	/// [`MlKem768`] names `StaticKey = Infallible`, so no static key exists to
	/// compare a share with.
	fn collapses_into(&self, key: &Infallible) -> bool {
		match *key {}
	}
}

/// The reply travels as a `KemCiphertext`, because [`MlKem768`] names
/// [`ReplyKind::Kem`].
impl KeyShare<MlKem768> for CiphertextShare {
	/// A ciphertext of the width of ML-KEM-768 passes the type check of
	/// FIPS 203 §7.3.
	fn from_octets(octets: &[u8]) -> Result<Self, KeyExchangeError> {
		let ciphertext = Ciphertext::<ml_kem::MlKem768>::try_from(octets);
		let expected = <ml_kem::MlKem768 as KemCore>::CiphertextSize::USIZE;
		let ciphertext = ciphertext.map_err(|_| KeyExchangeError::Width { expected, actual: octets.len() })?;
		Ok(Self(ciphertext))
	}

	fn to_octets(&self) -> Vec<u8> {
		self.0.to_vec()
	}

	/// [`MlKem768`] names `StaticKey = Infallible`, so no static key exists to
	/// compare a share with.
	fn collapses_into(&self, key: &Infallible) -> bool {
		match *key {}
	}
}

impl KeyExchange for MlKem768 {
	type Offer = EncapsulationShare;
	type Reply = CiphertextShare;
	type Pending = MlKemDecapsulationKey;
	type StaticKey = Infallible;

	const REPLY: ReplyKind = ReplyKind::Kem;

	/// FIPS 203 §8 places ML-KEM-768 in security category 3, a strength of
	/// 192 bits.
	fn strength() -> SecurityStrength {
		SecurityStrength::BITS_192
	}

	fn offer(mut rng: &mut dyn CryptoRngCore) -> (MlKemDecapsulationKey, EncapsulationShare) {
		let (decapsulation, encapsulation) = ml_kem::MlKem768::generate(&mut rng);
		(decapsulation, EncapsulationShare(encapsulation))
	}

	fn respond(
		offer: &EncapsulationShare,
		mut rng: &mut dyn CryptoRngCore,
	) -> Result<(CiphertextShare, SecretSlice<u8>), KeyExchangeError> {
		let encapsulated = offer.0.encapsulate(&mut rng).map_err(|()| KeyExchangeError::Refused)?;
		let (ciphertext, mut shared) = encapsulated;
		let secret = SecretSlice::from(shared.to_vec());
		shared.as_mut_slice().zeroize();
		Ok((CiphertextShare(ciphertext), secret))
	}

	fn complete(pending: &MlKemDecapsulationKey, reply: &CiphertextShare) -> Result<SecretSlice<u8>, KeyExchangeError> {
		let mut shared = pending.decapsulate(&reply.0).map_err(|()| KeyExchangeError::Refused)?;
		let secret = SecretSlice::from(shared.to_vec());
		shared.as_mut_slice().zeroize();
		Ok(secret)
	}

	fn static_key(_spki: SubjectPublicKeyInfoRef<'_>) -> Option<Infallible> {
		None
	}
}

/// Key generation draws `d`, then `z`, and offers the encapsulation key of
/// the ACVP vector.
#[test]
fn ml_kem_offers_the_key_of_its_key_generation_vector() {
	let seeds = [unhex(ACVP_KEYGEN_D), unhex(ACVP_KEYGEN_Z)].concat();
	let (_pending, offer) = MlKem768::offer(&mut PublishedDraw(seeds));
	assert_eq!(offer.to_octets(), unhex(ACVP_KEYGEN_EK));
}

/// An offer of the ACVP key, answered under the message `m` of the vector,
/// gives the ciphertext and the shared key of the vector.
#[test]
fn ml_kem_responds_as_its_encapsulation_vector() -> Result<(), KeyExchangeError> {
	let offer = EncapsulationShare::from_octets(&unhex(ACVP_ENCAP_EK))?;
	let (reply, shared) = MlKem768::respond(&offer, &mut PublishedDraw(unhex(ACVP_ENCAP_M)))?;

	let shared = shared.with(|secret| secret.to_vec());
	assert_eq!((reply.to_octets(), shared), (unhex(ACVP_ENCAP_C), unhex(ACVP_ENCAP_K)));
	Ok(())
}

/// The decapsulation key of the ACVP vector completes the ciphertext of the
/// vector with its shared key.
#[test]
fn ml_kem_completes_as_its_decapsulation_vector() -> Result<(), Box<dyn Error>> {
	let encoded = Encoded::<MlKemDecapsulationKey>::try_from(unhex(ACVP_DECAP_DK).as_slice())?;
	let pending = MlKemDecapsulationKey::from_bytes(&encoded);
	let reply = CiphertextShare::from_octets(&unhex(ACVP_DECAP_C))?;

	let shared = MlKem768::complete(&pending, &reply)?;
	assert_eq!(shared.with(|secret| secret.to_vec()), unhex(ACVP_DECAP_K));
	Ok(())
}

/// An encapsulation key whose first coefficient encodes as 4095, at or above
/// the modulus 3329, fails the modulus check of FIPS 203 §7.2.
#[test]
fn an_encapsulation_key_above_the_modulus_is_refused() {
	let mut key = unhex(ACVP_ENCAP_EK);
	key[0] = 0xff;
	key[1] |= 0x0f;

	let refused = EncapsulationShare::from_octets(&key);
	assert!(matches!(refused, Err(KeyExchangeError::Malformed)));
}

/// The `agreementKey` of a CMS opening names `id-alg-ml-kem-768` with no
/// parameters, so a key under another identifier, or with parameters, names
/// another algorithm.
#[test]
fn an_agreement_key_of_another_algorithm_is_refused() -> Result<(), KeyExchangeError> {
	let (_pending, offer) = MlKem768::offer(&mut OsRng);
	let key = offer.to_originator_key()?;
	let other = AlgorithmIdentifierOwned { oid: CURVE_X25519, parameters: None };
	let parameters = Any::encode_from(&ID_ML_KEM_768).ok();
	let with_parameters = AlgorithmIdentifierOwned { oid: ID_ML_KEM_768, parameters };

	let keys = [other, with_parameters].map(|algorithm| OriginatorPublicKey { algorithm, ..key.clone() });
	let refused = keys.map(|key| EncapsulationShare::from_originator_key(&key).err());
	assert_eq!(refused, [Some(KeyExchangeError::Algorithm); 2]);
	Ok(())
}

/// The reply travels in the CMS Finished as a `KemCiphertext` of the
/// ciphertext under the identifier of ML-KEM-768 (RFC 9629 §3).
#[test]
fn an_ml_kem_reply_travels_as_a_kem_ciphertext() -> Result<(), Box<dyn Error>> {
	let (_pending, offer) = MlKem768::offer(&mut OsRng);
	let (reply, _shared) = MlKem768::respond(&offer, &mut OsRng)?;

	let attribute = ReplyAttribute::of::<MlKem768>(&reply)?;
	let ReplyAttribute::KemCiphertext(KemCiphertext { kem, kemct }) = attribute else {
		return Err("an ML-KEM reply travels as a KEM ciphertext".into());
	};
	assert_eq!((kem.oid, kemct.as_bytes()), (ID_ML_KEM_768, reply.to_octets().as_slice()));
	Ok(())
}

/// A KEM reply travels as a `KemCiphertext` alone, so the parse of an ML-KEM
/// reply refuses the `OriginatorPublicKey` carrier of a DH reply.
#[test]
fn a_reply_in_the_dh_carrier_is_refused() -> Result<(), KeyExchangeError> {
	let (_pending, offer) = MlKem768::offer(&mut OsRng);
	let key = offer.to_originator_key()?;

	let refused = ReplyAttribute::OriginatorKey(key).reply::<MlKem768>();
	assert!(matches!(refused, Err(KeyExchangeError::Algorithm)));
	Ok(())
}

/// The `kem` of an ML-KEM reply names `id-alg-ml-kem-768` with no
/// parameters, so a ciphertext under another identifier, or with
/// parameters, names another algorithm.
#[test]
fn a_ciphertext_of_another_algorithm_is_refused() -> Result<(), Box<dyn Error>> {
	let (_pending, offer) = MlKem768::offer(&mut OsRng);
	let (reply, _shared) = MlKem768::respond(&offer, &mut OsRng)?;
	let kemct = OctetString::new(reply.to_octets())?;
	let other = AlgorithmIdentifierOwned { oid: CURVE_X25519, parameters: None };
	let parameters = Any::encode_from(&ID_ML_KEM_768).ok();
	let with_parameters = AlgorithmIdentifierOwned { oid: ID_ML_KEM_768, parameters };

	let carried = |kem| ReplyAttribute::KemCiphertext(KemCiphertext { kem, kemct: kemct.clone() });
	let refused = [other, with_parameters].map(|kem| carried(kem).reply::<MlKem768>().err());
	assert_eq!(refused, [Some(KeyExchangeError::Algorithm); 2]);
	Ok(())
}

/// The HPKE flow runs under ML-KEM-768.
#[tokio::test]
async fn ml_kem_runs_the_hpke_flow() -> Result<(), Box<dyn Error>> {
	assert_eq!(hpke_opens::<OnP384<MlKem768>>().await?, CONTENT);
	Ok(())
}

/// The CMS flow runs under ML-KEM-768.
#[tokio::test]
async fn ml_kem_runs_the_cms_flow() -> Result<(), Box<dyn Error>> {
	assert_eq!(cms_opens::<OnP384<MlKem768>>().await?, CONTENT);
	Ok(())
}

/// A session under ML-KEM-768 renews its epoch in band.
#[cfg(all(feature = "transport-multiplex", feature = "tcp", feature = "tokio"))]
#[tokio::test]
async fn ml_kem_renews_its_epoch() -> Result<(), Box<dyn Error>> {
	let renewed = super::super::renewal::renews_its_epoch::<OnP384<MlKem768>>(p384_identity).await?;
	assert!(renewed);
	Ok(())
}
