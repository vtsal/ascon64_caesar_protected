-- and_3TI

library ieee;
use ieee.std_logic_1164.ALL;

entity and_3TI is
    generic (N:integer:=32);
    port (

	xa, xb, ya, yb  : in  std_logic_vector(N-1 downto 0);
	m : in std_logic_vector(N*3 - 1 downto 0);
	o1, o2 		: out std_logic_vector(N-1 downto 0)
	);

end entity and_3TI;

architecture structural of and_3TI is

signal x1, x2, x3, y1, y2, y3, z1, z2, z3 : std_logic_vector(N-1 downto 0);

attribute keep : string;
attribute keep of x1, x2, x3, y1, y2, y3, z1, z2, z3 : signal is "true";

begin

x1 <= not xa xor m(N*2 - 1 downto N); -- resharing
x2 <= xb;
x3 <= m(N*2 - 1 downto N);
	
y1 <= ya; -- resharing
y2 <= yb xor m(N-1 downto 0);
y3 <= m(N-1 downto 0);

anda: entity work.and_3TI_a(dataflow)
   generic map(N => N)
	port map(
	xa => x2,
	xb => x3,
	ya => y2, 
	yb => y3,
	m => m(N*3-1 downto N*2),
	o  => z1

	);

andb: entity work.and_3TI_b(dataflow)
   generic map(N => N)
	port map(
	xa => x3,
	xb => x1,
	ya => y3, 
	yb => y1,
	m => m(N*3 - 1 downto N*2),
	o  => z2

	);

andc: entity work.and_3TI_c(dataflow)
   generic map(N => N)
	port map(
	xa => x1,
	xb => x2,
	ya => y1, 
	yb => y2,
	m => m(N*3-1 downto N*2),
	o  => z3

	);

o1 <= z1 xor z2;
o2 <= z3;

end structural;
