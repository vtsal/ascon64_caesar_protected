-- permutation

library ieee;
use ieee.std_logic_1164.ALL;
use ieee.numeric_std.all;

entity permutation_TI is
    generic (N: integer:=64);
    port (

   clk, rst : in std_logic;
	in0a, in1a, in2a, in3a, in4a  : in  std_logic_vector(N - 1 downto 0);
	in0b, in1b, in2b, in3b, in4b  : in  std_logic_vector(N - 1 downto 0);
	out0a, out1a, out2a, out3a, out4a : out std_logic_vector(N - 1 downto 0);
	out0b, out1b, out2b, out3b, out4b : out std_logic_vector(N - 1 downto 0);
	m : in std_logic_vector(3 * N - 1 downto 0);
	rcin : in std_logic_vector(7 downto 0);
	perm_start : in std_logic;
	done : out std_logic;
	state_debug : out std_logic_vector(3 downto 0)
	);

end entity permutation_TI;

architecture structural of permutation_TI is

type state_type is (S_START, S_0, S_1, S_2, S_3, S_4);
signal state, next_state : state_type;

signal run, clr_run, set_run, running, set_running, clr_running : std_logic;
signal x0a, x1a, x2a, x3a, x4a : std_logic_vector(N - 1 downto 0);
signal x0b, x1b, x2b, x3b, x4b : std_logic_vector(N - 1 downto 0);
signal x0_rega, x1_rega, x1_2_rega, x2_rega, x3_rega, x4_rega, x4_0_rega : std_logic_vector(N - 1 downto 0);
signal x0_regb, x1_regb, x1_2_regb, x2_regb, x3_regb, x4_regb, x4_0_regb : std_logic_vector(N - 1 downto 0);
signal next_x0_rega, next_x0_1_rega, next_x4_0_rega, next_x1_rega, next_x1_2_rega, next_x2_rega, next_x3_rega, next_x4_rega : std_logic_vector(N - 1 downto 0);
signal next_x0_regb, next_x0_1_regb, next_x4_0_regb, next_x1_regb, next_x1_2_regb, next_x2_regb, next_x3_regb, next_x4_regb : std_logic_vector(N - 1 downto 0);
signal x0_xor_x4a, x2rca, x1_xor_x2a, x3_xor_x4a : std_logic_vector(N - 1 downto 0);
signal x0_xor_x4b, x2rcb, x1_xor_x2b, x3_xor_x4b : std_logic_vector(N - 1 downto 0);
signal x0_xor_x4_rega, x0_xor_x4_regb, x3_xor_x4_rega, x3_xor_x4_regb : std_logic_vector(N - 1 downto 0); 

signal x0_1_rega, x0_reg_xor_x4_rega, not_x2_3_rega, x2_3_rega : std_logic_vector(N - 1 downto 0);
signal x0_1_regb, x0_reg_xor_x4_regb, not_x2_3_regb, x2_3_regb : std_logic_vector(N - 1 downto 0);

signal nx0_xor_x4a, nx1a, nx1_xor_x2a, nx3a, nx3_xor_x4a : std_logic_vector(N - 1 downto 0);
signal nx0_xor_x4b, nx1b, nx1_xor_x2b, nx3b, nx3_xor_x4b : std_logic_vector(N - 1 downto 0);

signal next_x2_3_rega, x3_xor_and_x2a, x0_reg_xor_x1_rega : std_logic_vector(N - 1 downto 0);
signal next_x2_3_regb, x3_xor_and_x2b, x0_reg_xor_x1_regb : std_logic_vector(N - 1 downto 0);

signal state0_en, state1_en, state2_en, state3_en, state4_en : std_logic; 

signal en_rc_reg : std_logic;
signal rc, rc_reg, next_rc_reg : std_logic_vector(7 downto 0);
signal next_rc_reg_hi, next_rc_reg_lo : std_logic_vector(3 downto 0);
signal and_in1a, and_in2a : std_logic_vector(N - 1 downto 0);
signal and_in1b, and_in2b : std_logic_vector(N - 1 downto 0);

signal and_outa : std_logic_vector(N - 1 downto 0); 
signal and_outb : std_logic_vector(N - 1 downto 0); 

signal and_sel : std_logic_vector(2 downto 0);

begin
-- control
  done <= not running; -- when done asserts, correct results are registered in output regs
  
-- stage 0
  x0a <= in0a when (run = '0') else x0_rega;  
  x1a <= in1a when (run = '0') else x1_rega;
  x2a <= in2a when (run = '0') else x2_rega;
  x3a <= in3a when (run = '0') else x3_rega;
  x4a <= in4a when (run = '0') else x4_rega;
  
  x0b <= in0b when (run = '0') else x0_regb;  
  x1b <= in1b when (run = '0') else x1_regb;
  x2b <= in2b when (run = '0') else x2_regb;
  x3b <= in3b when (run = '0') else x3_regb;
  x4b <= in4b when (run = '0') else x4_regb;

  rc <= rcin when (perm_start = '1') else rc_reg;
  next_rc_reg_hi <= std_logic_vector(unsigned(rc(7 downto 4)) - 1);
  next_rc_reg_lo <= std_logic_vector(unsigned(rc(3 downto 0)) + 1);
  next_rc_reg <= rcin when (perm_start = '1') else next_rc_reg_hi & next_rc_reg_lo;
  
  x0_xor_x4a <= x0a xor x4a;
  x0_xor_x4b <= x0b xor x4b;
  
  x2rca <= x2a(N - 1 downto 8) & (x2a(7 downto 0) xor rc);
  x2rcb <= x2b(N - 1 downto 8) & x2b(7 downto 0); -- constant only added to one share

  x1_xor_x2a <= x1a xor x2rca;
  x1_xor_x2b <= x1b xor x2rcb;
  x3_xor_x4a <= x3a xor x4a;
  x3_xor_x4b <= x3b xor x4b;

  next_x4_0_rega <= and_outa xor x3_xor_x4a;
  next_x4_0_regb <= and_outb xor x3_xor_x4b;
  
-- stage 1

  next_x0_1_rega <= x0_xor_x4a xor and_outa;
  next_x0_1_regb <= x0_xor_x4b xor and_outb;
  
-- stage 2

  next_x1_2_rega <= x1a xor and_outa;
  next_x1_2_regb <= x1b xor and_outb;
  
-- stage 3

  next_x2_3_rega <= x1_xor_x2a xor and_outa;
  next_x2_3_regb <= x1_xor_x2b xor and_outb;
  
  x0_reg_xor_x1_rega <= x0_1_rega xor x1_2_rega;
  x0_reg_xor_x1_regb <= x0_1_regb xor x1_2_regb;
  
  next_x1_rega <= x0_reg_xor_x1_rega xor (x0_reg_xor_x1_rega(60 downto 0) & x0_reg_xor_x1_rega(63 downto 61)) xor
                 (x0_reg_xor_x1_rega(38 downto 0) & x0_reg_xor_x1_rega(63 downto 39)); -- permutation
  next_x1_regb <= x0_reg_xor_x1_regb xor (x0_reg_xor_x1_regb(60 downto 0) & x0_reg_xor_x1_regb(63 downto 61)) xor
                 (x0_reg_xor_x1_regb(38 downto 0) & x0_reg_xor_x1_regb(63 downto 39)); -- permutation
                 
  out1a <= x1_rega; 
  out1b <= x1_regb;
  
-- stage 4

  x0_reg_xor_x4_rega <= x0_1_rega xor x4_0_rega;
  x0_reg_xor_x4_regb <= x0_1_regb xor x4_0_regb;
  
  next_x0_rega <= x0_reg_xor_x4_rega xor (x0_reg_xor_x4_rega(18 downto 0) & x0_reg_xor_x4_rega(63 downto 19)) xor
                 (x0_reg_xor_x4_rega(27 downto 0) & x0_reg_xor_x4_rega(63 downto 28)); -- permutation
  next_x0_regb <= x0_reg_xor_x4_regb xor (x0_reg_xor_x4_regb(18 downto 0) & x0_reg_xor_x4_regb(63 downto 19)) xor
                 (x0_reg_xor_x4_regb(27 downto 0) & x0_reg_xor_x4_regb(63 downto 28)); -- permutation
  
  out0a <= x0_rega;
  out0b <= x0_regb;
  
  not_x2_3_rega <= x2_3_rega;
  not_x2_3_regb <= x2_3_regb; -- only one share gets negated
  
  next_x2_rega <= not(not_x2_3_rega xor (not_x2_3_rega(0) & not_x2_3_rega(63 downto 1)) xor  
                 (not_x2_3_rega(5 downto 0) & not_x2_3_rega(63 downto 6))); -- permutation
  
  next_x2_regb <= not_x2_3_regb xor (not_x2_3_regb(0) & not_x2_3_regb(63 downto 1)) xor  
                 (not_x2_3_regb(5 downto 0) & not_x2_3_regb(63 downto 6)); -- permutation
  
  out2a <= x2_rega;
  out2b <= x2_regb;
  
  x3_xor_and_x2a <= x3a xor and_outa xor x2_3_rega;
  x3_xor_and_x2b <= x3b xor and_outb xor x2_3_regb;
  
  next_x3_rega <= x3_xor_and_x2a xor (x3_xor_and_x2a(9 downto 0) & x3_xor_and_x2a(63 downto 10)) xor
                 (x3_xor_and_x2a(16 downto 0) & x3_xor_and_x2a(63 downto 17)); -- permutation

  next_x3_regb <= x3_xor_and_x2b xor (x3_xor_and_x2b(9 downto 0) & x3_xor_and_x2b(63 downto 10)) xor
                 (x3_xor_and_x2b(16 downto 0) & x3_xor_and_x2b(63 downto 17)); -- permutation
               
  out3a <= x3_rega;
  out3b <= x3_regb;
  
  next_x4_rega <= x4_0_rega xor (x4_0_rega(6 downto 0) & x4_0_rega(63 downto 7)) xor
                 (x4_0_rega(40 downto 0) & x4_0_rega(63 downto 41)); -- permutation
  next_x4_regb <= x4_0_regb xor (x4_0_regb(6 downto 0) & x4_0_regb(63 downto 7)) xor
                 (x4_0_regb(40 downto 0) & x4_0_regb(63 downto 41)); -- permutation
                 
  out4a <= x4_rega;
  out4b <= x4_regb;
  
-- global and gate
  
  with and_sel select	
	and_in1a <= x0_xor_x4a    when "000",
	           x1a            when "001",
			   x1_xor_x2a     when "010",
			   x3a            when "011",
			   x3_xor_x4_rega when "100",
			   (others => '0') when others;
			   
  with and_sel select	
	and_in2a <= x1a        when "000",
	           x1_xor_x2a when "001",
			   x3a        when "010",
			   x3_xor_x4_rega when "011",
			   x0_xor_x4_rega when "100",
			   (others => '0') when others;
  
  with and_sel select	
	and_in1b <= x0_xor_x4b when "000",
	           x1b        when "001",
			   x1_xor_x2b when "010",
			   x3b        when "011",
			   x3_xor_x4_regb when "100",
			   (others => '0') when others;
			   
  with and_sel select	
	and_in2b <= x1b        when "000",
	           x1_xor_x2b when "001",
			   x3b        when "010",
			   x3_xor_x4_regb when "011",
			   x0_xor_x4_regb when "100",
			   (others => '0') when others;

  and_instance: entity work.and_3TI(structural)
   generic map(N => 64)
	port map(
	xa => and_in1a,
	xb => and_in1b,
	ya => and_in2a,
	yb => and_in2b,
	m => m, 
	o1  => and_outa,
	o2 => and_outb
	);
 
  sync_process: process(clk)
  begin
	if (rising_edge(clk)) then
	   if (rst = '1') then
			run <= '0';
			state <= S_START;
			running <= '0';
		else
			if (en_rc_reg = '1') then -- stage 0	
				rc_reg <= next_rc_reg;
			end if;

            if (state0_en = '1') then
                x4_0_rega <= next_x4_0_rega;
				x4_0_regb <= next_x4_0_regb;
				x3_xor_x4_rega <= x3_xor_x4a;
				x0_xor_x4_regb <= x0_xor_x4b;				
            end if;
            
            if (state1_en = '1') then
                x0_1_rega <= next_x0_1_rega;
				x0_1_regb <= next_x0_1_regb;
				x0_xor_x4_rega <= x0_xor_x4a;
				x3_xor_x4_regb <= x3_xor_x4b;
				x4_rega <= next_x4_rega;
				
            end if;
            
            if (state2_en = '1') then
                x1_2_rega <= next_x1_2_rega;
                x1_2_regb <= next_x1_2_regb;
                x0_rega <= next_x0_rega;
                x4_regb <= next_x4_regb;                
            end if;
            
            if (state3_en = '1') then
                x2_3_rega <= next_x2_3_rega;
				x2_3_regb <= next_x2_3_regb;
				x0_regb <= next_x0_regb;
				x1_rega <= next_x1_rega;
            end if;
            
            if (state4_en = '1') then
                x1_regb <= next_x1_regb;
                x2_rega <= next_x2_rega;
                x2_regb <= next_x2_regb;
                x3_rega <= next_x3_rega;
				x3_regb <= next_x3_regb;                
            end if;
            
            if (set_run = '1') then -- stage 4
				run <= '1';
			end if;
			if (clr_run = '1') then -- stage 4
				run <= '0';
			end if;
			if (set_running = '1') then
				running <= '1';
			end if;
			if (clr_running = '1') then
				running <= '0';
			end if;
			state <= next_state;
			end if;
		end if;
  end process;

  state_process: process(state, perm_start, rc(3 downto 0)) 
  begin
	--defaults

	state0_en <= '0';
	state1_en <= '0';
	state2_en <= '0';
	state3_en <= '0';
	state4_en <= '0';

	en_rc_reg <= '0';
	clr_run <= '0';
	set_run <= '0';
	set_running <= '0';
	clr_running <= '0';
	
	and_sel <= "000";
	state_debug <= x"F"; -- default
	
	case state is
		
		when S_START => 
		
			if (perm_start = '1') then
			    state0_en <= '1';
				set_running <= '1';
				en_rc_reg <= '1';
				next_state <= S_1;
			else
			   next_state <= S_START;
			end if;
			state_debug <= x"E";
			
		when S_0 => 
			
			state0_en <= '1';
			next_state <= S_1;
		    state_debug <= x"0";
			
		when S_1 => 
		    
		    state1_en <= '1';
			and_sel <= "001"; 
			next_state <= S_2;
			state_debug <= x"1";
			
		when S_2 => 
		    
		    state2_en <= '1';
			and_sel <= "010";
            next_state <= S_3;
			state_debug <= x"2";

        when S_3 => 

            state3_en <= '1';
		    and_sel <= "011";
			en_rc_reg <= '1';
			next_state <= S_4;
			state_debug <= x"3";
			
		when S_4 =>
		
		    state4_en <= '1';
			next_state <= S_0;
			and_sel <= "100";
			if (rc(3 downto 0) = x"c") then -- stop criteria
				clr_run <= '1';
				clr_running <= '1';
				next_state <= S_START;
			else 
				set_run <= '1';
				next_state <= S_0;
			end if;
			state_debug <= x"4";
			
		when others =>
		
	   end case;
    
	end process;
			
end structural;
