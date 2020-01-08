-------------------------------------------------------------------------------
--! @file       padding_unit.vhd
--! @brief      padding_unit for ldummy1
--! @project    CAESAR Candidate Evaluation
--! @author     Farnoud Farahmand
--! @copyright  Copyright (c) 2017 Cryptographic Engineering Research Group
--!             ECE Department, George Mason University Fairfax, VA, U.S.A.
--!             All rights Reserved.
--! @license    This project is released under the GNU Public License.
--!             The license and distribution terms for this file may be
--!             found in the file LICENSE in this distribution or at
--!             http://www.gnu.org/licenses/gpl-3.0.txt
--! @note       This is publicly available encryption source code that falls
--!             under the License Exception TSU (Technology and software-
--!             —unrestricted)
-------------------------------------------------------------------------------

library IEEE;
use IEEE.STD_LOGIC_1164.ALL;
use work.design_pkg.all;
use work.CAESAR_LWAPI_pkg.all;
use IEEE.NUMERIC_STD.ALL;

entity padding_unit is
    generic (
        G_DBLK_SIZE     : integer := 128
    );
    port(
        rst             : in  STD_LOGIC;
        clk             : in  STD_LOGIC;
        bdi_in          : in  STD_LOGIC_VECTOR (PW       -1 downto 0);
        bdi_valid_in    : in  STD_LOGIC;
        bdi_ready_in    : in  STD_LOGIC;
        bdo_in          : in  STD_LOGIC_VECTOR (PW       -1 downto 0);
        round_in        : in  STD_LOGIC_VECTOR (PW       -1 downto 0);

        bdi_out         : out  STD_LOGIC_VECTOR (PW       -1 downto 0);
        bdi_valid_out   : out  STD_LOGIC;
        bdi_ready_out   : out  STD_LOGIC;
        bdo_out         : out  STD_LOGIC_VECTOR (PW       -1 downto 0);
        round_out       : out  STD_LOGIC_VECTOR (PW       -1 downto 0);

        bdi_eot_in      : in  STD_LOGIC;
        bdi_eot_out     : out STD_LOGIC;

        bdi_pad_loc     : in  STD_LOGIC_VECTOR (PWdiv8   -1 downto 0);
        bdi_valid_bytes : in  STD_LOGIC_VECTOR (PWdiv8   -1 downto 0);

        end_of_block    : in  STD_LOGIC;
        bdi_type	: in  STD_LOGIC_VECTOR (4	-1 downto 0);
        pad_block   : out STD_LOGIC;
        sel_bdo_pad : in STD_LOGIC
    );

end padding_unit;

architecture behavioral of padding_unit is

    type t_state is (S_RESET, S_GEN_PAD10, S_GEN_PAD00);
    signal state            : t_state;
    signal state_next       : t_state;
    signal sel_out          : std_logic_vector(1 downto 0);
    signal bdi_valid_pad	: std_logic;
    signal sel_bdi_ctrl     : std_logic;
    signal sel_bdi_ctrl_other: std_logic;
    signal bdi_eot_pad      : std_logic;
    signal ad_exist_next    : std_logic;
    signal ad_exist_r       : std_logic;
    signal padded_bdi       : std_logic_vector(PW    -1 downto 0);
    signal pad_loc_sig      : std_logic_vector(PW    -1 downto 0);
    signal valid_bytes_sig  : std_logic_vector(PW    -1 downto 0);
    signal pad_loc_r_sig      : std_logic_vector(PW    -1 downto 0);
    signal valid_bytes_r_sig  : std_logic_vector(PW    -1 downto 0);
    signal bdi_pad_loc_r      : std_logic_vector(PWdiv8    -1 downto 0);
    signal bdi_valid_bytes_r  : std_logic_vector(PWdiv8    -1 downto 0);
    signal all_zeros        : std_logic_vector(PW    -1 downto 0);
    signal one_zeros        : std_logic_vector(PW    -1 downto 0);
    signal padded_bdo       : std_logic_vector(PW    -1 downto 0);
    signal padded_round     : std_logic_vector(PW    -1 downto 0);
    constant num_words		: integer := get_words(G_DBLK_SIZE, PW) -1;
    signal last_word_of_blk : std_logic;

begin

----------------------------------------------------
-- Datapath
----------------------------------------------------

    valid_bytes : entity work.bitEXP_ValidBytes(structure)
		port map(
                input      => bdi_valid_bytes,
                output     => valid_bytes_sig
        );

    pad_loc : entity work.bitEXP_PadLoc(structure)
		port map(
                input      => bdi_pad_loc,
                output     => pad_loc_sig
        );

    --valid_bytes_r : entity work.bitEXP_ValidBytes(structure)
	--	port map(
    --            input      => bdi_valid_bytes_r,
    --            output     => valid_bytes_r_sig
    --    );

    --pad_loc_r : entity work.bitEXP_PadLoc(structure)
	--	port map(
    --            input      => bdi_pad_loc_r,
    --            output     => pad_loc_r_sig
    --    );


    with sel_out select bdi_out  <=
        padded_bdi  when "00",
        one_zeros   when "01",
        all_zeros   when others;

	bdi_eot_out	   <= bdi_eot_in when
        ((last_word_of_blk = '1') and (end_of_block = '1')) else bdi_eot_pad;
	padded_bdi	   <= (bdi_in and valid_bytes_sig) or pad_loc_sig;
	bdi_valid_out  <= bdi_valid_in  when (sel_bdi_ctrl = '0') else bdi_valid_pad;
    bdi_ready_out  <= bdi_ready_in  when (sel_bdi_ctrl = '0') else '0';
    pad_block      <= sel_bdi_ctrl;

    padded_bdo	   <= (bdo_in and valid_bytes_sig); --or pad_loc_r_sig --valid_bytes_r_sig
    bdo_out        <= padded_bdo when sel_bdo_pad = '0' else bdo_in;
    padded_round   <= (round_in and valid_bytes_sig) or pad_loc_sig;  --pad_loc_r_sig
    round_out      <= padded_round;
    --bdi_ready_out  <= bdi_ready_in  when (sel_bdi_ctrl_other = '0') else '0';

    last_word_of_blk <= bdi_valid_in and bdi_ready_in and bdi_eot_in;

----------------------------------------------------
-- Controller
----------------------------------------------------


    p_fsm: process(clk)
    begin
        if rising_edge(clk) then
            if (rst = '1') then
                state <= S_RESET;
                sel_bdi_ctrl <= '0';
                bdi_pad_loc_r     <= (others => '0');
                bdi_valid_bytes_r <= (others => '1');
                --ad_exist_r <= '0';
            else
                --ad_exist_r  <= ad_exist_next;
                state       <= state_next;
				if ((last_word_of_blk = '1') and (end_of_block = '0'))or
                    (ad_exist_r= '0') then --and (bdi_type = HDR_NPUB)
                    sel_bdi_ctrl <= '1';
				elsif (bdi_eot_pad = '1') then
                    sel_bdi_ctrl <= '0';
				end if;
                if (bdi_eot_in = '1')and((bdi_type = HDR_MSG)or(bdi_type = HDR_CT))
                    and(bdi_ready_in = '1')then
                    bdi_pad_loc_r     <= bdi_pad_loc;
                    bdi_valid_bytes_r <= bdi_valid_bytes;
                end if;
                if (bdi_ready_in = '1' and bdi_valid_in='1') and (bdi_type = HDR_AD)then
                    ad_exist_r<= '1';
                end if;
            end if;
        end if;
    end process;


    p_comb: process(state, bdi_eot_in, bdi_ready_in, end_of_block, bdi_pad_loc,
            bdi_valid_in, last_word_of_blk, bdi_type, ad_exist_r)
    begin
        --! Default values
        state_next  <= state;
        bdi_eot_pad <= '0';
        bdi_valid_pad <= '0';
        sel_out     <= "00";
        all_zeros   <= (others => '0');
        one_zeros   <= ((PW-1) => '1', others => '0');
        ad_exist_next <= ad_exist_r;

        case state is

            when S_RESET =>
                if ((last_word_of_blk = '1') and (end_of_block = '0')) then --and (bdi_type /= HDR_NPUB)
                    if unsigned(bdi_pad_loc) = 0 then
                        state_next <= S_GEN_PAD10;
                    else
                        state_next <= S_GEN_PAD00;
                    end if;
                --elsif (ad_exist_r= '0') and(bdi_type = HDR_NPUB) and
                --    (bdi_ready_in = '1') and (bdi_valid_in='1') then
                --    state_next <= S_GEN_PAD10;

                --elsif bdi  add later
                end if;

			when S_GEN_PAD10 =>
				sel_out		<= "01";
				bdi_valid_pad	<= '1';
				if (bdi_ready_in = '1') then
					if (end_of_block = '1') then
                        bdi_eot_pad <= '1';
						state_next  <= S_RESET;
					else
						state_next  <= S_GEN_PAD00;
					end if;
				end if;

			when S_GEN_PAD00 =>
				sel_out		<= "10";
				bdi_valid_pad	<= '1';
				if (bdi_ready_in = '1') then
					if (end_of_block = '1') then
						bdi_eot_pad <= '1';
						state_next  <= S_RESET;
					end if;
				end if;

        end case;
    end process;

end behavioral;
