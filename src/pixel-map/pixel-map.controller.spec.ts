import { Test, TestingModule } from '@nestjs/testing';
import { PixelMapController } from './pixel-map.controller';

describe('PixelMapController', () => {
  let controller: PixelMapController;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [PixelMapController],
    }).compile();

    controller = module.get<PixelMapController>(PixelMapController);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });
});
