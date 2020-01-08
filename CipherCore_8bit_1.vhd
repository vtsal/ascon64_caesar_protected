-------------------------------------------------------------------------------
-------------------------------------------------------------------------------
--! @file       CipherCore_8bit_1.vhd
--! @author     
--! @brief      Top-level CipherCore for AES-GCM
-------------------------------------------------------------------------------

library ieee;
use ieee.std_logic_1164.ALL;
use work.AEAD_pkg.all;
use work.design_pkg.all;

entity CipherCore_8bit is
    generic (
        --! Reset behavior
        G_ASYNC_RSTN    : boolean := False; --! Async active low reset
        --! Block size (bits)
        G_DBLK_SIZE     : integer := 128;   --! Data
        G_KEY_SIZE      : integer := 32;    --! Key
        G_TAG_SIZE      : integer := 128;   --! Tag
        --! The number of bits required to hold block size expressed in
        --! bytes = log2_ceil(G_DBLK_SIZE/8)
        G_LBS_BYTES      : integer := 4;
        --! Maximum supported AD/message/ciphertext length = 2^G_MAX_LEN-1
        G_MAX_LEN       : integer := SINGLE_PASS_MAX
    );
    port (
        --! Global
        clk             : in  std_logic;
        rst             : in  std_logic;
        --! PreProcessor (data)
        keya, keyb      : in  std_logic_vector(8       -1 downto 0);
        bdia, bdib      : in  std_logic_vector(8      -1 downto 0);
		  m					: in std_logic_vector(RW - 1 downto 0);
        --! PreProcessor (controls)
        key_ready       : out std_logic;
        key_valid       : in  std_logic;
        key_update      : in  std_logic;
        decrypt         : in  std_logic;
        bdi_ready       : out std_logic;
        bdi_valid       : in  std_logic;
        bdi_type        : in  std_logic_vector(3 downto 0);
        bdi_partial     : in  std_logic;
        bdi_eot         : in  std_logic;
        bdi_eoi         : in  std_logic;
        bdi_size        : in  std_logic_vector(2 downto 0);
        bdi_valid_bytes : in  std_logic_vector(0 downto 0);
        --bdi_pad_loc     : in  std_logic_vector(G_DBLK_SIZE/8    -1 downto 0);
        --! PostProcessor
        bdoa, bdob      : out std_logic_vector(8      -1 downto 0);
        bdo_valid       : out std_logic;
        bdo_ready       : in  std_logic;
        bdo_size        : out std_logic_vector(G_LBS_BYTES+1    -1 downto 0);
		  end_of_block		: out std_logic;
        msg_auth        : out std_logic;
		  msg_auth_ready	: in std_logic;
        msg_auth_valid  : out std_logic
    );
end entity CipherCore_8bit;

architecture structural of CipherCore_8bit is
    signal en_key               : std_logic;
    signal en_bdi               : std_logic;
	signal en_bdo 			    : std_logic;
    signal clr_bdi              : std_logic;
	signal ld_bdo				: std_logic;
    signal sel_tag              : std_logic;
	signal ld_ctr				: std_logic_vector(3 downto 0);
	signal key_sel          : std_logic;

    signal decrypt_reg     : std_logic;
	 signal decrypt_last    : std_logic;
    signal rc					: std_logic_vector(7 downto 0);
	signal reg_ready            : std_logic;
	signal perm_start           : std_logic;
	signal perm_done            : std_logic;
	signal bank0_op1_sel        : std_logic_vector(1 downto 0);
	 
	signal bank0_op2_sel        : std_logic_vector(1 downto 0);
	signal op1_sel              : std_logic_vector(1 downto 0);
	signal op2_sel              : std_logic_vector(1 downto 0);
	signal bank0_en             : std_logic;
	signal bank1_en             : std_logic;
	signal bank2_en             : std_logic;
   signal perm_reset           : std_logic;
   signal last_PT_sel          : std_logic;	 
	 
begin

    u_cc_dp:
    entity work.CipherCore_Datapath_8bit(structural)
    port map (
        clk             => clk              ,
        rst             => rst              ,

        --! Input Processor
        keya             => keya              ,
        keyb             => keyb              ,
		  bdia             => bdia              ,
		  bdib             => bdib              ,
		  ld_ctr		    => ld_ctr			  ,
		  m				 => m,

        --! Output Processor
        bdoa             => bdoa              ,
        bdob             => bdob              ,
		  msg_auth_valid  => msg_auth_valid   ,

        --! Controller
		  decrypt        => decrypt_reg,
		  decrypt_last   => decrypt_last,
		  key_sel        => key_sel,
        en_key          => en_key           ,
        en_bdi          => en_bdi           ,
		ld_bdo          => ld_bdo	        ,
		en_bdo				=> en_bdo			  ,
        clr_bdi         => clr_bdi          ,
        sel_tag         => sel_tag          ,
		rc					=> rc,
		perm_start      => perm_start,
	    perm_done       => perm_done,
	    bank0_op1_sel   => bank0_op1_sel,
        bank0_op2_sel   => bank0_op2_sel,	    
		op1_sel         => op1_sel,
		op2_sel         => op2_sel,
	     bank0_en        => bank0_en,
	     bank1_en        => bank1_en,
	     bank2_en        => bank2_en,
		 perm_reset      => perm_reset
    );

    u_cc_ctrl:
    entity work.CipherCore_Controller_8bit(behavioral)
    port map (
        clk             => clk              ,
        rst             => rst              ,

        --! Input
        key_ready       => key_ready        ,
        key_valid       => key_valid        ,
        key_update      => key_update       ,
        decrypt         => decrypt          ,
		  decrypt_reg_out => decrypt_reg      ,
		  decrypt_last    => decrypt_last     ,
        bdi_ready       => bdi_ready        ,
        bdi_valid       => bdi_valid        ,
		  bdi_type      => bdi_type         ,
        bdi_eot         => bdi_eot          ,
        bdi_eoi         => bdi_eoi          ,
		  key_sel	      => key_sel ,

        ld_ctr_out      => ld_ctr           ,
        en_key          => en_key           ,
        en_bdi          => en_bdi           ,
		  en_bdo			=> en_bdo			  ,
        clr_bdi         => clr_bdi          ,
		  ld_bdo			=> ld_bdo			  ,
        sel_tag         => sel_tag          ,

        rc				=> rc,
	    perm_start      => perm_start,
	    perm_done       => perm_done,
	    bank0_op1_sel   => bank0_op1_sel,
		bank0_op2_sel   => bank0_op2_sel,
	    op1_sel         => op1_sel,
		op2_sel         => op2_sel,
		 bank0_en        => bank0_en,
	    bank1_en        => bank1_en,
	    bank2_en        => bank2_en,
		perm_reset      => perm_reset,

        --! Output
        msg_auth        => msg_auth         ,
		msg_auth_ready  => msg_auth_ready   ,
		end_of_block    => end_of_block     ,
        bdo_ready       => bdo_ready        ,
        bdo_valid       => bdo_valid
    );

end structural;
