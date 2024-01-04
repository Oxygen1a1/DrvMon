import os
import re


insert_str = """  <PropertyGroup Condition="'$(Configuration)|$(Platform)'=='Debug|x64'">
  <OutDir>$(SolutionDir)bin\$(Platform)\$(Configuration)\</OutDir>
  </PropertyGroup>
  <PropertyGroup Condition="'$(Configuration)|$(Platform)'=='Release|x64'">
  <OutDir>$(SolutionDir)bin\$(Platform)\$(Configuration)\</OutDir>
  </PropertyGroup>
  <PropertyGroup Condition="'$(Configuration)|$(Platform)'=='Debug|x64'">
  <IntDir>$(ProjectDir)obj\(Platform)\$(Configuration)\</IntDir>
  </PropertyGroup>
  <PropertyGroup Condition="'$(Configuration)|$(Platform)'=='Release|x64'">
    <IntDir>$(ProjectDir)obj\(Platform)\$(Configuration)\</IntDir>
  </PropertyGroup>
  <PropertyGroup Condition="'$(Configuration)|$(Platform)'=='Debug|x86'">
  <OutDir>$(SolutionDir)bin\$(Platform)\$(Configuration)\</OutDir>
  </PropertyGroup>
  <PropertyGroup Condition="'$(Configuration)|$(Platform)'=='Release|x86'">
  <OutDir>$(SolutionDir)bin\$(Platform)\$(Configuration)\</OutDir>
  </PropertyGroup>
  <PropertyGroup Condition="'$(Configuration)|$(Platform)'=='Debug|x86'">
  <IntDir>$(ProjectDir)obj\(Platform)\$(Configuration)\</IntDir>
  </PropertyGroup>
  <PropertyGroup Condition="'$(Configuration)|$(Platform)'=='Release|x86'">
    <IntDir>$(ProjectDir)obj\(Platform)\$(Configuration)\</IntDir>
  </PropertyGroup>
"""



pattern=re.compile(r'.*\.vcxproj$')

try:
    os.rmdir('..\\bin')
    os.rmdir('include')
    os.rmdir('src')
    os.rmdir('obj')
except FileNotFoundError:
    print("not find!\r\n")
#create dir
try:
    os.mkdir('..\\bin')
    os.mkdir('include')
    os.mkdir('src')
    os.mkdir('obj')
except FileExistsError:
    print("has exits")

cur_dir=os.getcwd();

for filename in os.listdir(cur_dir):
    if(pattern.match(filename)):
        break
with open(filename,'r',encoding='utf-8') as file:
    lines=file.readlines()

# finb str idx
idx=-1
for i,line in enumerate(lines):
    if line.strip()=='<PropertyGroup Label="UserMacros" />':
        idx=i
        break
if(idx!=-1):
    lines.insert(idx+1,insert_str)
    with open(filename,'w',encoding='utf-8') as file:
        file.writelines(lines)



