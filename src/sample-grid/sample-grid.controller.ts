import {
  Controller,
  Get,
  Post,
  Body,
  Patch,
  Param,
  Delete,
  UseGuards,
} from '@nestjs/common';
import { SampleGridService } from './sample-grid.service';
import { CreateSampleGridDto } from './dto/create-sample-grid.dto';
import { UpdateSampleGridDto } from './dto/update-sample-grid.dto';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { ApiTags, ApiBearerAuth } from '@nestjs/swagger';

@ApiTags('Sample Grids')
@ApiBearerAuth()
@UseGuards(JwtAuthGuard)
@Controller('sample-grids')
export class SampleGridController {
  constructor(private readonly sampleGridService: SampleGridService) {}

  @Get()
  findAll() {
    return this.sampleGridService.findAll();
  }

  @Get(':id')
  findOne(@Param('id') id: string) {
    return this.sampleGridService.findOne(id);
  }

  @Post()
  create(@Body() createSampleGridDto: CreateSampleGridDto) {
    return this.sampleGridService.create(createSampleGridDto);
  }

  @Patch(':id')
  update(
    @Param('id') id: string,
    @Body() updateSampleGridDto: UpdateSampleGridDto,
  ) {
    return this.sampleGridService.update(id, updateSampleGridDto);
  }

  @Delete(':id')
  remove(@Param('id') id: string) {
    return this.sampleGridService.remove(id);
  }
}
