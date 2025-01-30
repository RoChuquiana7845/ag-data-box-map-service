import {
  Controller,
  Get,
  Post,
  Body,
  Patch,
  Param,
  Delete,
  UseGuards,
  SetMetadata,
} from '@nestjs/common';
import { ManagementRegionService } from './management-region.service';
import { CreateManagementRegionDto } from './dto/create-management-region.dto';
import { UpdateManagementRegionDto } from './dto/update-management-region.dto';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { ApiTags, ApiBearerAuth } from '@nestjs/swagger';
import { RolesGuard } from 'src/auth/guards/roles.guard';

@ApiTags('Management Regions')
@ApiBearerAuth()
@UseGuards(JwtAuthGuard, RolesGuard)
@Controller('management-regions')
export class ManagementRegionController {
  constructor(
    private readonly managementRegionService: ManagementRegionService,
  ) {}

  @UseGuards(JwtAuthGuard)
  @Get()
  findAll() {
    return this.managementRegionService.findAll();
  }

  @UseGuards(JwtAuthGuard)
  @Get(':id')
  findOne(@Param('id') id: string) {
    return this.managementRegionService.findOne(id);
  }

  @SetMetadata('role', 'admin')
  @Post()
  create(@Body() createManagementRegionDto: CreateManagementRegionDto) {
    return this.managementRegionService.create(createManagementRegionDto);
  }

  @SetMetadata('role', 'admin')
  @Patch(':id')
  update(
    @Param('id') id: string,
    @Body() updateManagementRegionDto: UpdateManagementRegionDto,
  ) {
    return this.managementRegionService.update(id, updateManagementRegionDto);
  }

  @SetMetadata('role', 'admin')
  @Delete(':id')
  remove(@Param('id') id: string) {
    return this.managementRegionService.remove(id);
  }
}
