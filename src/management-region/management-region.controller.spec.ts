import { Test, TestingModule } from '@nestjs/testing';
import { ManagementRegionController } from './management-region.controller';

describe('ManagementRegionController', () => {
  let controller: ManagementRegionController;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [ManagementRegionController],
    }).compile();

    controller = module.get<ManagementRegionController>(
      ManagementRegionController,
    );
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });
});
